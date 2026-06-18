package handshake

import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class HandshakeSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

  private val secrets: Gen[Array[Byte]] =
    Gen.nonEmptyListOf(arbitrary[Byte]).map(_.toArray)

  test("same secret -> identical pairId, safetyNumber, pairKey (both sides agree, FR-001)"):
    forAll(secrets) { s =>
      val a = Handshake.init(s)
      val b = Handshake.init(s)
      assert(a.pairId == b.pairId)
      assert(a.safetyNumber == b.safetyNumber)
      assert(a.pairKey.sameElements(b.pairKey))
    }

  test("tampered secret -> different pairId, so the pairing is rejected (FR-001)"):
    forAll(secrets, secrets) { (s1, s2) =>
      whenever(!s1.sameElements(s2)) {
        assert(Handshake.init(s1).pairId != Handshake.init(s2).pairId)
      }
    }

  test("safety number is six 5-digit groups"):
    val sn = Handshake.init("oob".getBytes).safetyNumber
    assert(sn.split(" ").length == 6)
    assert(sn.split(" ").forall(g => g.length == 5 && g.forall(_.isDigit)))
