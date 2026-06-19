package ping

import notify.Notification
import notify.Notification.{Digest, NotificationToken}
import crypto.Crypto
import privacy.Privacy
import java.security.SecureRandom
import scala.collection.mutable

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
  private val rounds = mutable.Map.empty[String, Digest] // aggregation label (hex) -> digest

  val label: String            = Privacy.DevLabel
  def metadataPrivate: Boolean = false

  /** Receiver-side: seal a one-hot token for a buddy. sealed = nonce ‖ AEAD(serverKey, token). */
  def issueToken(bitPosition: Int, aggLabel: Array[Byte]): Array[Byte] =
    val nonce = new Array[Byte](Crypto.NonceBytes)
    rng.nextBytes(nonce)
    val ct = Crypto.aeadSeal(serverKey, nonce, Array.emptyByteArray,
      Notification.serialize(NotificationToken(bitPosition, aggLabel)))
    nonce ++ ct

  /** Sender-side submit: flips exactly the token's bit under its label. Rejects forged/tampered
    * blobs (AEAD authentication). */
  def signal(sealedToken: Array[Byte]): Either[String, Unit] =
    if sealedToken.length < Crypto.NonceBytes then Left("malformed sealed token")
    else
      val (nonce, ct) = sealedToken.splitAt(Crypto.NonceBytes)
      Crypto
        .aeadOpen(serverKey, nonce, Array.emptyByteArray, ct)
        .flatMap(Notification.deserialize)
        .map { tok =>
          val k = hex(tok.label)
          rounds.update(k, rounds.getOrElse(k, Digest.empty).set(tok.bitPosition))
        }

  /** Per-client digest. Returns a carrier (all-zero, uniform) when the client has no waiting
    * mail, so the response never reveals whether — or from which buddy — mail arrived. */
  def digest(aggLabel: Array[Byte]): Digest = rounds.getOrElse(hex(aggLabel), Digest.carrier)

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString
