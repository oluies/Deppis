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

  /** Derive the symmetric pairing values from the out-of-band shared secret.
    *
    * ==PQ-intent binding (US7 strip-downgrade defense)==
    * `pqRequired` is the authenticated out-of-band pairing intent — "this pairing MUST be
    * post-quantum". BOTH sides set it from the SAME OOB agreement, and it is folded (domain-separated
    * by a `"mm/pq-required"` step) into the derivation so a MITM who flips the intent bit on one side
    * makes the two sides derive DIFFERENT `pairId`/`safetyNumber`/`pairKey` — the out-of-band safety
    * number comparison then fails, exactly as a tampered secret would. This binds the PQ intent to the
    * authenticated channel, so an attacker who STRIPS the initiator's `kemPublicKey` cannot silently
    * demote a party that expected PQ (that party fails closed at `addBuddy`; see `Engine.addBuddy`).
    *
    * BACKWARD COMPATIBILITY: when `pqRequired == false` the derivation is BYTE-IDENTICAL to the
    * pre-change classical pairing (the raw `sharedSecret` is used unchanged), so existing classical
    * pairIds / safety numbers do not move (pinned by `HandshakeSpec`). */
  def init(sharedSecret: Array[Byte], pqRequired: Boolean = false): PairInit =
    // A domain-separated step folds the PQ-intent bit into the derivation ONLY when set, so a
    // `pqRequired = true` pairing derives entirely different values from a `pqRequired = false` one.
    // The derived `effective` is a transient secret — wiped in `finally` (it is a fresh copy; the
    // caller's `sharedSecret` is untouched). When the bit is unset we alias `sharedSecret` directly and
    // must NOT wipe it, so the wipe is gated on `pqRequired`.
    val effective =
      if pqRequired then Kdf.hmacSha256(sharedSecret, "mm/pq-required".getBytes(UTF_8))
      else sharedSecret
    try
      val pairKey = Kdf.hmacSha256(effective, "mm/pair-key".getBytes(UTF_8))
      val pairId = hex(Kdf.hmacSha256(effective, "mm/pair-id".getBytes(UTF_8))).take(32)
      val safety = safetyNumber(Kdf.hmacSha256(effective, "mm/safety".getBytes(UTF_8)))
      PairInit(pairId, safety, pairKey)
    finally if pqRequired then java.util.Arrays.fill(effective, 0.toByte)

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  /** Six space-separated 5-digit groups (Signal-style human comparison code). Each group draws
    * 3 HMAC bytes (24 bits) before reducing mod 100000, so the full 00000–99999 range is used
    * (18 of the 32 HMAC-SHA256 output bytes). */
  private def safetyNumber(b: Array[Byte]): String =
    (0 until 6)
      .map { i =>
        val v = (((b(3 * i) & 0xff) << 16) | ((b(3 * i + 1) & 0xff) << 8) | (b(
          3 * i + 2
        ) & 0xff)) % 100000
        f"$v%05d"
      }
      .mkString(" ")
