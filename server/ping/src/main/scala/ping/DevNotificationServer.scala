package ping

import notify.Notification
import notify.Notification.{Digest, NotificationToken}
import crypto.Crypto
import privacy.Privacy
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters.*

/** Dev PING notification subsystem (T030, FR-003/FR-004). Aggregates receiver-sealed tokens by
  * bitwise-OR over a shared label and emits one digest per client, injecting an all-zero carrier
  * for traffic uniformity (FR-012). This dev implementation provides NO access-pattern privacy
  * (the real oblivious sort/scan/compaction is the enclave sidecar, T053) and is labeled
  * `DEV, NO METADATA PRIVACY` (Constitution IV).
  *
  * Tokens are sealed with AEAD under the server key, so a sender holding one token can flip ONLY
  * its own encoded bit and cannot forge another buddy's bit or a different label (FR-003): any
  * tampered or forged blob fails authentication. (Dev simplification: the receiver shares the
  * symmetric server key to seal; the real path seals under the server's attested public key.) */
final class DevNotificationServer(serverKey: Array[Byte]):
  require(serverKey.length == Crypto.KeyBytes, s"server key must be ${Crypto.KeyBytes} bytes")

  private val rng    = new SecureRandom()
  // (roundId, aggregation label hex) -> digest; ConcurrentHashMap.compute makes the per-key OR
  // atomic under concurrent submissions. Keying by round honors the proto's per-round scope:
  // signals in different rounds never mix, and a fetch only clears its own round.
  private val rounds = new ConcurrentHashMap[(Long, String), Digest]()

  /** Sliding retention window: entries for rounds more than this many behind the newest signaled
    * round are evicted, bounding map growth even for a (round,label) that is never fetched. This
    * also realizes the spec's "bound how long undelivered notifications are retained" edge case. */
  private val RetentionRounds: Long = 16L

  val label: String            = Privacy.DevLabel
  def metadataPrivate: Boolean = false

  /** Receiver-side: seal a one-hot token for a buddy. sealed = nonce ‖ AEAD(serverKey, token). */
  def issueToken(bitPosition: Int, aggLabel: Array[Byte]): Array[Byte] =
    val nonce = new Array[Byte](Crypto.NonceBytes)
    rng.nextBytes(nonce)
    val ct = Crypto.aeadSeal(serverKey, nonce, Array.emptyByteArray,
      Notification.serialize(NotificationToken(bitPosition, aggLabel)))
    nonce ++ ct

  /** Sender-side submit: flips exactly the token's bit under (round, label). Rejects
    * forged/tampered blobs (AEAD authentication). */
  def signal(roundId: Long, sealedToken: Array[Byte]): Either[String, Unit] =
    if sealedToken.length < Crypto.NonceBytes then Left("malformed sealed token")
    else
      val (nonce, ct) = sealedToken.splitAt(Crypto.NonceBytes)
      Crypto
        .aeadOpen(serverKey, nonce, Array.emptyByteArray, ct)
        .flatMap(Notification.deserialize)
        .map { tok =>
          val k = (roundId, hex(tok.label))
          // atomic OR: a concurrent signal for the same (round,label) cannot clobber another's bit.
          rounds.compute(k, (_, cur) => (if cur == null then Digest.empty else cur).set(tok.bitPosition))
          evictBefore(roundId - RetentionRounds)
          ()
        }

  /** Per-client digest for a round (non-destructive peek). Returns a carrier (all-zero, uniform)
    * when the client has no waiting mail, so the response never reveals whether — or from which
    * buddy — mail arrived. */
  def digest(roundId: Long, aggLabel: Array[Byte]): Digest =
    Option(rounds.get((roundId, hex(aggLabel)))).getOrElse(Digest.carrier)

  /** Consume-on-read for a round: atomically return the client's digest and clear its bits so a
    * retrieved notification is not re-reported. Returns a carrier when there is no waiting mail.
    * Map growth is bounded by the retention window even for rounds that are never fetched (see
    * `RetentionRounds` / `evictBefore`). */
  def digestAndReset(roundId: Long, aggLabel: Array[Byte]): Digest =
    Option(rounds.remove((roundId, hex(aggLabel)))).getOrElse(Digest.carrier)

  /** Number of distinct rounds currently retained (test/observability hook). */
  def retainedRounds: Int = rounds.keySet().asScala.map(_._1).toSet.size

  /** Drop entries for rounds strictly older than `minRound` (weakly-consistent, atomic per key). */
  private def evictBefore(minRound: Long): Unit =
    if minRound > 0 then rounds.keySet().removeIf(k => k._1 < minRound)

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString
