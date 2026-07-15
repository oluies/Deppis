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

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  test("BACKWARD COMPAT: pqRequired=false default derivation is byte-identical to a pinned vector"):
    // The PQ-intent binding (US7) MUST NOT move the classical pairing. Pin the pre-change values for a
    // fixed secret; the default and the explicit `pqRequired = false` path both reproduce them exactly.
    val default = Handshake.init("oob".getBytes)
    val explicitFalse = Handshake.init("oob".getBytes, pqRequired = false)
    assert(
      default.pairId == "f9f9b587573ffa4a71f2fa0e08c40f55",
      s"pairId drifted: ${default.pairId}"
    )
    assert(
      default.safetyNumber == "67141 14023 06183 97302 31422 58308",
      s"safety number drifted: ${default.safetyNumber}"
    )
    assert(
      hex(default.pairKey) == "f7fc266d624c4475b9a69035b1de4e705574309b4c796f0317f464fb63140c5c",
      s"pairKey drifted: ${hex(default.pairKey)}"
    )
    assert(explicitFalse.pairId == default.pairId, "pqRequired=false must equal the default")
    assert(explicitFalse.safetyNumber == default.safetyNumber)
    assert(explicitFalse.pairKey.sameElements(default.pairKey))

  test("PQ-INTENT BINDING: flipping pqRequired yields a DIFFERENT safety number (MITM caught)"):
    // A MITM that flips the authenticated PQ-intent bit on one side makes the two sides derive different
    // safety numbers, so the out-of-band comparison fails — exactly like a tampered secret.
    forAll(secrets) { s =>
      val classical = Handshake.init(s, pqRequired = false)
      val required = Handshake.init(s, pqRequired = true)
      assert(classical.pairId != required.pairId)
      assert(classical.safetyNumber != required.safetyNumber)
      assert(!classical.pairKey.sameElements(required.pairKey))
    }

  test("PQ-INTENT BINDING: both sides agreeing on pqRequired=true derive the SAME values"):
    forAll(secrets) { s =>
      val a = Handshake.init(s, pqRequired = true)
      val b = Handshake.init(s, pqRequired = true)
      assert(a.pairId == b.pairId)
      assert(a.safetyNumber == b.safetyNumber)
      assert(a.pairKey.sameElements(b.pairKey))
    }
