package notify

import notify.Notification.{Digest, NotificationToken}
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class NotificationSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

  private val positions: Gen[Int]      = Gen.choose(0, Notification.MaxBits - 1)
  private val labels: Gen[Array[Byte]] = Gen.listOf(arbitrary[Byte]).map(_.toArray)

  test("serialize/deserialize round-trips token (bit position + label)"):
    forAll(positions, labels) { (pos, lbl) =>
      val Right(t) = Notification.deserialize(Notification.serialize(NotificationToken(pos, lbl))): @unchecked
      assert(t.bitPosition == pos)
      assert(t.label.sameElements(lbl))
    }

  test("digest set/get and OR compose one-hot bits"):
    forAll(positions, positions) { (a, b) =>
      val d = Digest.empty.set(a).or(Digest.empty.set(b))
      assert(d.get(a) && d.get(b))
      assert(d.popcount == (if a == b then 1 else 2))
    }

  test("carrier digest is empty (uniform, reveals nothing)"):
    assert(Digest.carrier.isEmpty)
    assert(Digest.carrier.bytes.length == Notification.DigestBytes)

  test("out-of-range bit position is rejected"):
    assert(Notification.deserialize(Array(0xff.toByte, 0xff.toByte)).isLeft) // 65535 >= 512
