package frame

import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class FrameSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

  private val payloads: Gen[Array[Byte]] =
    Gen.choose(0, Frame.MaxPayload).flatMap(n => Gen.listOfN(n, arbitrary[Byte]).map(_.toArray))

  test("pad/unpad round-trips for any payload within bound"):
    forAll(payloads) { p =>
      val fr = Frame.pad(p).toOption.get
      assert(fr.length == Frame.Size)
      assert(Frame.unpad(fr).toOption.get.sameElements(p))
    }

  test("every frame is exactly 256 bytes regardless of payload (size uniformity)"):
    forAll(Gen.choose(0, Frame.MaxPayload)) { n =>
      assert(Frame.pad(new Array[Byte](n)).toOption.get.length == Frame.Size)
    }

  test("payload larger than max is rejected"):
    assert(Frame.pad(new Array[Byte](Frame.MaxPayload + 1)).isLeft)

  test("carrier is a valid empty-payload 256-byte frame"):
    val c = Frame.carrier()
    assert(c.length == Frame.Size)
    assert(Frame.unpad(c).toOption.get.isEmpty)
