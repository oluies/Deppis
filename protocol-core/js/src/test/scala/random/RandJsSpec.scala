package random

import org.scalatest.funsuite.AnyFunSuite

/** Contract test for the cryptographic RNG (Scala.js, Web Crypto `crypto.getRandomValues`) under
  * Node. Holds the JS build to the SAME observable contract as the JVM `SecureRandom` build
  * (`random.RandSpec`): correct length, non-zero, non-constant, broad value coverage — so a broken
  * `getRandomValues` binding (wrong typed-array, truncation, byte-conversion bug) is caught before
  * it can silently weaken AEAD nonces / cover-traffic keys (FR-012, Constitution I). */
class RandJsSpec extends AnyFunSuite:

  test("bytes(n) returns exactly n bytes for the sizes the engine uses (incl. 0)"):
    for n <- Seq(0, 1, 12, 16, 32, 256) do
      assert(Rand.bytes(n).length == n, s"length mismatch for n=$n")

  test("bytes(0) is empty"):
    assert(Rand.bytes(0).isEmpty)

  test("a 32-byte draw is not all-zero (would indicate a dead RNG / bad binding)"):
    assert(Rand.bytes(32).exists(_ != 0.toByte))

  test("two successive draws differ (not a constant/fixed buffer)"):
    assert(!Rand.bytes(32).sameElements(Rand.bytes(32)))

  test("draws are not trivially low-entropy: a large sample covers many distinct byte values"):
    val distinct = Rand.bytes(4096).distinct.length
    assert(distinct > 200, s"only $distinct distinct byte values in 4096 draws — suspicious")
