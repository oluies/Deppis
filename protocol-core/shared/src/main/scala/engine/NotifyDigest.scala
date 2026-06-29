package engine

import token.RetrievalToken

/** The PING notify digest layout (T041b): 512 one-hot buddy bits (FR-015), one per buddy. The
  * single source of truth for the per-buddy bit derivation — the engine and every test/e2e must use
  * this, so a change can't silently leave a test mirroring stale logic. */
object NotifyDigest:
  /** Digest size in bits (= obsd `MAX_BIT`, 64 bytes). */
  val Bits: Int = 512

  /** The bit a pair signals/checks IN A GIVEN ROUND, derived from the shared pair key AND the public
    * round id (so both sides agree without any extra channel).
    *
    * T041c (collision-free notify): rotating the bit per round makes any collision between two of a
    * receiver's buddies TRANSIENT rather than permanent. The receiver therefore serves a buddy only
    * when its set bit is UNAMBIGUOUS that round (no sibling shares it) — a guaranteed hit, so the
    * read-token stream is non-recurrent (FR-014) unconditionally; an ambiguous round defers to a
    * cover read and the buddies re-signal next round, where rotation almost surely separates them.
    * See `Engine.tick`. (This realizes T041c's GOAL via per-round rotation rather than a static
    * pairing-time lease, which the lease-less, derive-from-shared-secret architecture cannot carry;
    * design: specs/.../design/notify-bit-lease.md.) */
  def bit(pairKey: Array[Byte], roundId: Long): Int =
    val b = RetrievalToken.derive(pairKey, "notify-bit", "", roundId)
    (((b(0) & 0xff) << 8) | (b(1) & 0xff)) % Bits

  /** Is `bit` set in `digest`? */
  def isSet(digest: Array[Byte], bit: Int): Boolean =
    val idx = bit >> 3
    idx < digest.length && (digest(idx) & (1 << (bit & 7))) != 0
