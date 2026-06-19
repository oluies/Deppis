package schedule

import frame.Frame
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class ScheduleSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

  private val maybePayload: Gen[Option[Array[Byte]]] =
    Gen.option(Gen.choose(0, Frame.MaxPayload).map(new Array[Byte](_)))

  test("every round emits one 256-byte frame and a retrieval, real or idle (shape uniformity)"):
    forAll(maybePayload) { p =>
      val plan = Schedule.planRound(1L, p).toOption.get
      assert(plan.frame.length == Frame.Size)
      assert(plan.retrieve)
    }

  test("idle round is a carrier, real round is real — but identical wire size (FR-012)"):
    val real = Schedule.planRound(1L, Some("hi".getBytes)).toOption.get
    val idle = Schedule.planRound(1L, None).toOption.get
    assert(real.kind == Schedule.FrameKind.Real)
    assert(idle.kind == Schedule.FrameKind.Carrier)
    assert(real.frame.length == idle.frame.length)
