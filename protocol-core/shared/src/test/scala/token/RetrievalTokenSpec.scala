package token

import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class RetrievalTokenSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:
  private val key = "test-key-0123456789abcdef".getBytes

  test("token is 32 bytes and deterministic for equal inputs"):
    forAll { (s: String, r: String, c: Long) =>
      val t1 = RetrievalToken.derive(key, s, r, c)
      val t2 = RetrievalToken.derive(key, s, r, c)
      assert(t1.length == RetrievalToken.Length)
      assert(RetrievalToken.equalsCT(t1, t2))
    }

  test("distinct counters yield distinct tokens (non-recurrence, FR-014)"):
    forAll { (s: String, r: String, c1: Long, c2: Long) =>
      whenever(c1 != c2):
        assert(
          !RetrievalToken.equalsCT(
            RetrievalToken.derive(key, s, r, c1),
            RetrievalToken.derive(key, s, r, c2)
          )
        )
    }

  test("field boundaries are unambiguous (length-prefixed): (ab,c) != (a,bc)"):
    assert(
      !RetrievalToken.equalsCT(
        RetrievalToken.derive(key, "ab", "c", 1L),
        RetrievalToken.derive(key, "a", "bc", 1L)
      )
    )
