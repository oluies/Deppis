package handshake

import kdf.Kdf
import java.nio.charset.StandardCharsets.UTF_8

/** Add-friend handshake (T023, FR-001). Two users exchange a shared secret out of band (QR /
  * safety-number comparison). From that single secret both sides derive — symmetrically and
  * deterministically — the same `pairId`, the same human-comparable `safetyNumber`, and the
  * same per-pair `pairKey`. If the secret was tampered with in transit, the two sides derive
  * DIFFERENT safety numbers, so the out-of-band comparison fails and the pairing is rejected.
  *
  * Domain-separated HMAC-SHA256 derivations (Kdf) are used here. The asymmetric X25519/ML-KEM
  * key agreement is layered in later (Phase D) and does not change this comparison logic. */
object Handshake:
  final case class PairInit(pairId: String, safetyNumber: String, pairKey: Array[Byte])

  def init(sharedSecret: Array[Byte]): PairInit =
    val pairKey = Kdf.hmacSha256(sharedSecret, "mm/pair-key".getBytes(UTF_8))
    val pairId  = hex(Kdf.hmacSha256(sharedSecret, "mm/pair-id".getBytes(UTF_8))).take(32)
    val safety  = safetyNumber(Kdf.hmacSha256(sharedSecret, "mm/safety".getBytes(UTF_8)))
    PairInit(pairId, safety, pairKey)

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  /** Six space-separated 5-digit groups (Signal-style human comparison code). Each group draws
    * 3 HMAC bytes (24 bits) before reducing mod 100000, so the full 00000–99999 range is used
    * (18 of the 32 HMAC-SHA256 output bytes). */
  private def safetyNumber(b: Array[Byte]): String =
    (0 until 6)
      .map { i =>
        val v = (((b(3 * i) & 0xff) << 16) | ((b(3 * i + 1) & 0xff) << 8) | (b(3 * i + 2) & 0xff)) % 100000
        f"$v%05d"
      }
      .mkString(" ")
