package integration.scale

import integration.RoundStack
import org.scalatest.funsuite.AnyFunSuite

/** T033a (US3, SC-005): a user holding 512 simultaneous conversations over a REAL server round
  * ([[RoundStack]]). All 512 buddies are paired; a few at the edges and in the middle are active
  * at once, the rest idle. Every active conversation must deliver in both directions, with no
  * conversation blocking another, while alice still makes one read and one write per round. */
class ScaleConversationsSpec extends AnyFunSuite:

  test("512 conversations held; active ones at the edges and middle all deliver"):
    val stack = RoundStack()
    try
      val alice = stack.device("alice")
      val buddies = (0 until 512).map(i => stack.device(f"b$i%03d"))
      buddies.foreach(stack.pair(alice, _))

      val active = Seq(0, 1, 255, 256, 510, 511).map(buddies)
      active.foreach(b => b.send(alice, s"${b.name}->alice"))
      active.foreach(b => alice.send(b, s"alice->${b.name}"))

      // Idle buddies are offline (they would only send cover traffic); the active ones tick.
      val last = stack.run(alice +: active, 1, 200)(
        alice.texts.size == active.size && active.forall(_.texts.nonEmpty)
      )
      assert(alice.texts.toSet == active.map(b => s"${b.name}->alice").toSet, alice.received)
      active.foreach(b => assert(b.texts == Seq(s"alice->${b.name}"), b.received))
      info(s"${active.size} active of 512 delivered both ways by round $last")
    finally stack.close()
