package engine

import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** T032a: the engine drives the notify/store backend through [[RoundTransport]] — notify-before-
  * retrieval (FR-004). Uses an in-memory fake transport shared by two engines (a sender and a
  * receiver) so a real delivery round-trips without a network. */
class RoundTransportSpec extends AnyFunSuite:

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  /** In-memory store + a controllable "mail waiting" flag. Shared between the two engines so a frame
    * one submits can be retrieved by the other (single-use). */
  private final class FakeTransport(val store: mutable.Map[String, Array[Byte]] = mutable.Map.empty)
      extends RoundTransport:
    var mail: Boolean       = false
    var acceptSubmit: Boolean = true // set false to simulate a transient backend failure on send
    def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
      if acceptSubmit then store(hex(token)) = frame
      acceptSubmit
    def mailWaiting(roundId: Long, clientLabel: Array[Byte]): Boolean = mail
    def retrieve(token: Array[Byte]): Option[Array[Byte]] = store.remove(hex(token))

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")

  /** A confirmed buddy on an engine with the given transport + role. */
  private def confirmedEngine(t: RoundTransport, role: BuddyRole): (Engine, String) =
    val e = Engine(Some(t), clientLabel = "client".getBytes)
    val r = e.addBuddy(secret("shared"), role).toOption.get
    e.confirmBuddy(r.pairId, matched = true)
    e.drainEvents() // discard buddyConfirmed
    (e, r.pairId)

  test("no transport ⇒ tick emits no delivery events (local-only default)"):
    val e = Engine()
    val r = e.addBuddy(secret("s"), BuddyRole.Initiator).toOption.get
    e.confirmBuddy(r.pairId, matched = true)
    e.drainEvents()
    assert(e.tick(1).isRight)
    assert(e.drainEvents().isEmpty)

  test("tick emits notified when the backend reports mail waiting (FR-004)"):
    val t = FakeTransport()
    val (bob, _) = confirmedEngine(t, BuddyRole.Responder)
    t.mail = true
    bob.tick(1)
    assert(bob.drainEvents().contains(EngineEvent.Notified(1)))

  test("tick emits no notified when no mail is waiting"):
    val t = FakeTransport()
    val (bob, _) = confirmedEngine(t, BuddyRole.Responder)
    t.mail = false
    bob.tick(1)
    assert(!bob.drainEvents().exists(_.isInstanceOf[EngineEvent.Notified]))

  test("a message submitted by the sender is retrieved + surfaced by the receiver"):
    val t = FakeTransport()
    val (alice, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    val (bob, _)        = confirmedEngine(t, BuddyRole.Responder)
    assert(alice.sendMessage(pairId, "meet at noon") == Right(1))
    alice.tick(1)                       // Alice submits the frame to the shared store
    assert(alice.drainEvents().isEmpty) // sender sees nothing on its own retrieval
    bob.tick(2)                         // Bob retrieves it
    val received = bob.drainEvents().collect { case EngineEvent.MessageReceived(p, txt, _) => (p, txt) }
    assert(received == Seq((pairId, "meet at noon")))

  test("notify is emitted BEFORE the retrieved message (notify-before-retrieval order)"):
    val t = FakeTransport()
    val (alice, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    val (bob, _)        = confirmedEngine(t, BuddyRole.Responder)
    alice.sendMessage(pairId, "hi")
    alice.tick(1)
    t.mail = true
    bob.tick(2)
    val evs = bob.drainEvents()
    val ni  = evs.indexWhere(_.isInstanceOf[EngineEvent.Notified])
    val mi  = evs.indexWhere(_.isInstanceOf[EngineEvent.MessageReceived])
    assert(ni >= 0 && mi >= 0 && ni < mi, s"expected notified before messageReceived, got $evs")

  test("single-use: the same message is not delivered twice"):
    val t = FakeTransport()
    val (alice, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    val (bob, _)        = confirmedEngine(t, BuddyRole.Responder)
    alice.sendMessage(pairId, "once")
    alice.tick(1)
    bob.tick(2)
    assert(bob.drainEvents().exists(_.isInstanceOf[EngineEvent.MessageReceived]))
    bob.tick(3)
    assert(!bob.drainEvents().exists(_.isInstanceOf[EngineEvent.MessageReceived]))

  test("a failed submit keeps the frame queued and retries it next round (no message loss)"):
    val t = FakeTransport()
    val (alice, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    val (bob, _)        = confirmedEngine(t, BuddyRole.Responder)
    alice.sendMessage(pairId, "important")
    t.acceptSubmit = false
    alice.tick(1)               // submit fails → frame NOT stored, stays queued
    assert(t.store.isEmpty)
    bob.tick(2)
    assert(!bob.drainEvents().exists(_.isInstanceOf[EngineEvent.MessageReceived]))
    t.acceptSubmit = true
    alice.tick(3)               // retry succeeds
    bob.tick(4)
    val got = bob.drainEvents().collect { case EngineEvent.MessageReceived(_, txt, _) => txt }
    assert(got == Seq("important"))

  test("the carrier flag reflects whether a real frame was actually submitted (fail+retry uniform)"):
    val t = FakeTransport()
    val (alice, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    alice.sendMessage(pairId, "x")
    t.acceptSubmit = false
    val failed = alice.tick(1).toOption.get
    assert(failed.carrier, "a failed send must report as a carrier round, not a real one")
    t.acceptSubmit = true
    val ok = alice.tick(2).toOption.get
    assert(!ok.carrier, "a successful send reports a real round")
    // An empty round (nothing queued) is a carrier too.
    assert(alice.tick(3).toOption.get.carrier)

  test("multiple waiting messages are all drained in one receive round"):
    val t = FakeTransport()
    val (alice, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    val (bob, _)        = confirmedEngine(t, BuddyRole.Responder)
    alice.sendMessage(pairId, "m1"); alice.tick(1)
    alice.sendMessage(pairId, "m2"); alice.tick(2)
    bob.tick(3) // both m1 and m2 are waiting under sequential tokens; drain both this round
    val got = bob.drainEvents().collect { case EngineEvent.MessageReceived(_, txt, _) => txt }
    assert(got == Seq("m1", "m2"))
