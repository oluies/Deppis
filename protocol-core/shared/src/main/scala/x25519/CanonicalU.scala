package x25519

/** Raised when an attacker-supplied peer X25519 public key is REJECTED — either a non-canonical
  * encoding (`u >= p`) or a low-order / degenerate point (all-zero ECDH result). A dedicated subtype
  * of `IllegalArgumentException` so callers can catch EXACTLY a peer-key rejection (e.g. the
  * `DoubleRatchet` treating the frame as an undecryptable carrier) WITHOUT also swallowing an
  * unrelated `IllegalArgumentException` from a genuine local bug (a corrupted key/chain reaching the
  * KDF). Same type on both platforms (`x25519.X25519` is a platform object; this class lives in the
  * shared source root and is linked into JVM and Scala.js alike). */
final class PeerKeyRejected(message: String, cause: Throwable)
    extends IllegalArgumentException(message, cause):
  def this(message: String) = this(message, null)

/** The SINGLE SOURCE OF TRUTH for the X25519 peer u-coordinate canonicality predicate (`u < p`,
  * p = 2^255 - 19, RFC 7748), shared byte-for-byte by the JVM and Scala.js `x25519.X25519` objects so
  * the two builds accept EXACTLY the same peer encodings. Pure Scala over PUBLIC, attacker-supplied
  * bytes (`scala.math.BigInt`, cross-platform) — no secret-dependent branch, no curve arithmetic
  * (Constitution I/II).
  *
  * NOTE: `crypto.HybridKem.validatePeerX25519` (a separate JVM-only module with a stronger explicit
  * small-subgroup blocklist) keeps its own copy of this predicate to avoid a cross-module dependency;
  * THIS object is the reference definition of the `u < p` range check. */
object CanonicalU:
  val KeyBytes: Int = 32

  // Curve25519 field prime p = 2^255 - 19. A well-formed u-coordinate satisfies u < p after the
  // unused top bit is masked; an out-of-range `p <= u < 2^255` encoding could otherwise be reduced
  // differently by different peers, silently disagreeing on the DH leg — a cross-platform oracle.
  private val P25519: BigInt = (BigInt(1) << 255) - 19

  /** Reject a non-canonical peer u-coordinate (`u >= p` after masking bit 255), or a wrong length,
    * with `PeerKeyRejected`. Interprets `peerPublic` little-endian with bit 255 cleared (RFC 7748
    * ignores the top bit on decode). */
  def requireCanonical(peerPublic: Array[Byte]): Unit =
    if peerPublic.length != KeyBytes then
      throw new PeerKeyRejected(s"X25519 peer public key must be $KeyBytes bytes")
    var u = BigInt(0)
    var i = KeyBytes - 1
    while i >= 0 do
      val b = if i == KeyBytes - 1 then peerPublic(i) & 0x7f else peerPublic(i) & 0xff
      u = (u << 8) | BigInt(b)
      i -= 1
    if u >= P25519 then throw new PeerKeyRejected("X25519: non-canonical peer u-coordinate (>= p)")
