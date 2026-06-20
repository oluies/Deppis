package random

import org.scalatest.funsuite.AnyFunSuite

/** Contract test for the cryptographic RNG (JVM `SecureRandom`). `Rand.bytes` feeds AEAD nonces,
  * per-session cover keys, and carrier-frame keys — a regression that returns a constant, zero, or
  * short buffer would silently break BOTH AEAD security and cover-traffic unlinkability (FR-012)
  * with nothing else to catch it. These assertions pin the observable contract; the JS (Web Crypto)
  * build is held to the identical contract by `random.RandJsSpec`. */
class RandSpec extends AnyFunSuite:

  test("bytes(n) returns exactly n bytes for the sizes the engine uses (incl. 0)"):
    for n <- Seq(0, 1, 12, 16, 32, 256) do
      assert(Rand.bytes(n).length == n, s"length mismatch for n=$n")

  test("bytes(0) is empty"):
    assert(Rand.bytes(0).isEmpty)

  test("a 32-byte draw is not all-zero (would indicate a dead RNG)"):
    assert(Rand.bytes(32).exists(_ != 0.toByte))

  test("two successive draws differ (not a constant/fixed buffer)"):
    // For 32 cryptographically-random bytes, P(equal) = 2^-256 — a collision means a broken RNG.
    assert(!Rand.bytes(32).sameElements(Rand.bytes(32)))

  test("draws are not trivially low-entropy: a large sample covers many distinct byte values"):
    // 4096 strong-random bytes should exercise nearly the whole 0..255 range; a stuck/biased
    // generator (e.g. always 0x00, or a tiny cycle) would collapse this count.
    val distinct = Rand.bytes(4096).distinct.length
    assert(distinct > 200, s"only $distinct distinct byte values in 4096 draws — suspicious")
