package integration.concurrency

import integration.RoundStack
import org.scalatest.funsuite.AnyFunSuite

/** T033 (US3, FR-006): concurrent conversations over a REAL server round — engines on the JVM
  * ObliviousStore + NotificationService via gRPC ([[RoundStack]]), not the in-memory fake. Each
  * device makes one write, one signal and one read per round (FR-012), so concurrent conversations
  * share those slots; none may block another, including one whose peer has gone silent. */
class ConcurrentConversationsSpec extends AnyFunSuite:

  test("three conversations in flight in the same round all deliver, both directions"):
    val stack = RoundStack()
    try
      val alice = stack.device("alice")
      val peers = Seq("bob", "carol", "dave").map(stack.device)
      peers.foreach(stack.pair(alice, _))

      // All six messages are queued before round 1: three conversations in flight at once.
      peers.foreach(p => alice.send(p, s"alice->${p.name}"))
      peers.foreach(p => p.send(alice, s"${p.name}->alice"))

      val all = alice +: peers
      val last = stack.run(all, 1, 60)(
        alice.texts.size == 3 && peers.forall(_.texts.nonEmpty)
      )
      assert(alice.texts.toSet == peers.map(p => s"${p.name}->alice").toSet, alice.received)
      peers.foreach(p => assert(p.texts == Seq(s"alice->${p.name}"), p.received))
      info(s"all 6 delivered by round $last")
    finally stack.close()

  test("a conversation whose peer is offline does not block the others"):
    val stack = RoundStack()
    try
      val alice = stack.device("alice")
      val Seq(bob, carol, dave) = Seq("bob", "carol", "dave").map(stack.device)
      Seq(bob, carol, dave).foreach(stack.pair(alice, _))

      // Dave is offline for the whole run: alice's message to him is never acknowledged, so its
      // stop-and-wait head stays outstanding. It must not hold up bob's and carol's.
      Seq(bob, carol, dave).foreach(p => alice.send(p, s"alice->${p.name}"))
      bob.send(alice, "bob->alice")
      carol.send(alice, "carol->alice")

      val online = Seq(alice, bob, carol)
      val last = stack.run(online, 1, 60)(
        alice.texts.size == 2 && bob.texts.nonEmpty && carol.texts.nonEmpty
      )
      assert(bob.texts == Seq("alice->bob"), bob.received)
      assert(carol.texts == Seq("alice->carol"), carol.received)
      assert(alice.texts.toSet == Set("bob->alice", "carol->alice"), alice.received)
      assert(dave.texts.isEmpty)
      info(s"bob and carol served by round $last while dave stayed offline")

      // Dave comes back: his conversation resumes and alice's message reaches him.
      val back = stack.run(online :+ dave, last + 1, last + 60)(dave.texts.nonEmpty)
      assert(dave.texts == Seq("alice->dave"), dave.received)
      info(s"dave received after returning, by round $back")
    finally stack.close()
