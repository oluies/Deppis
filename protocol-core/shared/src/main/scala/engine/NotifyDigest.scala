package engine

import token.RetrievalToken

/** The PING notify digest layout (T041b): 512 one-hot buddy bits (FR-015), one per buddy. The
  * single source of truth for the per-buddy bit derivation — the engine and every test/e2e must use
  * this, so a future change (e.g. the T041c collision-free bit-lease) can't silently leave a test
  * mirroring stale logic. */
object NotifyDigest:
  /** Digest size in bits (= obsd `MAX_BIT`, 64 bytes). */
  val Bits: Int = 512

  /** The bit a pair signals/checks, derived from the shared pair key so both sides agree.
    * NOTE: this can collide at ~birthday rate over 512 bits; a pairing-time bit-lease is the
    * collision-free refinement (T041c). */
  def bit(pairKey: Array[Byte]): Int =
    val b = RetrievalToken.derive(pairKey, "notify-bit", "", 0L)
    (((b(0) & 0xff) << 8) | (b(1) & 0xff)) % Bits

  /** Is `bit` set in `digest`? */
  def isSet(digest: Array[Byte], bit: Int): Boolean =
    val idx = bit >> 3
    idx < digest.length && (digest(idx) & (1 << (bit & 7))) != 0
