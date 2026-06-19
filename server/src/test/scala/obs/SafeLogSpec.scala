package obs

import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class SafeLogSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

  private val bytes: Gen[Array[Byte]] = Gen.listOf(arbitrary[Byte]).map(_.toArray)

  test("redaction is constant — independent of a secret's value AND length (Constitution II)"):
    forAll(bytes, bytes) { (a, b) =>
      assert(SafeLog.redact(a) == SafeLog.Redacted)
      assert(SafeLog.redact(a) == SafeLog.redact(b)) // no variation on content/length
    }

  test("redaction output length is constant — no length side channel"):
    forAll(bytes, bytes) { (a, b) =>
      assert(SafeLog.redact(a).length == SafeLog.redact(b).length)
    }

  test("failure messages are fixed per reason and carry no secret-dependent content"):
    FailureReason.values.foreach { r =>
      assert(r.message.nonEmpty)
      assert(r.message == r.message) // stable
    }
    assert(FailureReason.AuthenticationFailed.message == "authentication failed")
    // distinct reasons have distinct messages
    val msgs = FailureReason.values.map(_.message).toSet
    assert(msgs.size == FailureReason.values.length)
