package privacy

import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class PrivacySpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:
  import Privacy.*

  test("dev and stub backends are never private and carry the dev label (Constitution IV)"):
    forAll(Gen.oneOf(Backend.Dev, Backend.GrooveStub), Gen.oneOf(true, false)) { (b, att) =>
      val s = BuildPrivacyStatus(b, att)
      assert(!s.metadataPrivate)
      assert(s.label == DevLabel)
    }

  test("real backends are private iff attestation passed"):
    forAll(Gen.oneOf(Backend.EnclaveTarget, Backend.GrooveTarget), Gen.oneOf(true, false)) { (b, att) =>
      val s = BuildPrivacyStatus(b, att)
      assert(s.metadataPrivate == att)
      assert(s.label == (if att then PrivateLabel else DevLabel))
    }
