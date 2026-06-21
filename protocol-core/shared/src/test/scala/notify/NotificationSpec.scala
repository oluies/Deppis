package notify

import notify.Notification.{Digest, NotificationToken}
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class NotificationSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

  private val positions: Gen[Int] = Gen.choose(0, Notification.MaxBits - 1)
  private val labels: Gen[Array[Byte]] = Gen.listOf(arbitrary[Byte]).map(_.toArray)

  // full Long range incl. negatives — uint64 round_ids >= 2^63 surface as negative Long in ScalaPB
  test("serialize/deserialize round-trips (round, bit position, label) over the full uint64 range"):
    forAll(arbitrary[Long], positions, labels) { (round, pos, lbl) =>
      val Right((r, t)) =
        Notification.deserialize(
          Notification.serialize(round, NotificationToken(pos, lbl))
        ): @unchecked
      assert(r == round)
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
    // 8 round bytes + bit 0xffff (65535 >= 512)
    assert(Notification.deserialize(new Array[Byte](8) ++ Array(0xff.toByte, 0xff.toByte)).isLeft)

  test("a too-short token is rejected"):
    assert(Notification.deserialize(Array(0x00.toByte, 0x01.toByte)).isLeft)
