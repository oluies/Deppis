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
    var mail: Boolean         = false
    var acceptSubmit: Boolean = true // set false to simulate a transient backend failure on send
    // The observable submit trace: (token, frame) per write — what an observer of the store sees.
    val submits = mutable.ArrayBuffer.empty[(Array[Byte], Array[Byte])]
    def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
      submits += ((token, frame))
      if acceptSubmit then store(hex(token)) = frame
      acceptSubmit
    def mailWaiting(roundId: Long, clientLabel: Array[Byte]): Boolean = mail
    // The observable fetch trace: the token read on each retrieve call (what the store sees).
    val retrieves = mutable.ArrayBuffer.empty[Array[Byte]]
    def retrieve(token: Array[Byte]): Option[Array[Byte]] =
      retrieves += token
      store.remove(hex(token))

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

  test("cover traffic: every round makes exactly one store write whether active or idle"):
    val t = FakeTransport()
    val (e, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    // 5 rounds: alternate active (a real message queued) and idle (nothing queued).
    for r <- 1 to 5 do
      if r % 2 == 1 then e.sendMessage(pairId, s"msg$r")
      e.tick(r)
    assert(t.submits.size == 5, "exactly one store write per round (no missing/extra writes)")
    assert(e.internalAnomalyCount == 0, "no internal invariant breaks in normal operation")

  test("one store write per round holds under a transient submit failure (actual store, not attempts)"):
    val t = FakeTransport()
    val (e, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    // Idle round with the backend up ⇒ exactly one cover frame lands in the store.
    e.tick(1)
    assert(t.store.size == 1, "an idle round writes one cover frame")
    // Idle round with the backend down ⇒ one write ATTEMPT, nothing lands (store unchanged).
    t.acceptSubmit = false
    e.tick(2)
    assert(t.submits.size == 2, "still exactly one write attempt this round")
    assert(t.store.size == 1, "the failed cover write does not land — and is not silently doubled")
    // Real message while the backend is down ⇒ one attempt, frame stays queued, store unchanged.
    e.sendMessage(pairId, "later")
    e.tick(3)
    assert(t.submits.size == 3 && t.store.size == 1)
    // Backend recovers ⇒ the queued real frame is delivered (no loss).
    t.acceptSubmit = true
    e.tick(4)
    assert(t.store.size == 2, "the retried real frame now lands")

  test("active and idle STORE-WRITE traces are indistinguishable (T041 send path)"):
    // Two clients: one sends a real message every round, one is idle every round. An observer of the
    // store's WRITE side sees, per round, one write with a fixed-size frame under a fixed-size token
    // — IDENTICAL for both, so it cannot tell active from idle by the write trace (FR-012, send path).
    //
    // NOT yet uniform (tracked, T041 fetch path + T042): the FETCH side still leaks (an active
    // receiver drains more frames than an idle one), and frame *content* (real plaintext vs all-zero
    // carrier) distinguishes until the message-content ratchet is in the frame path. This asserts the
    // store-WRITE shape only.
    val rounds = 20
    val active = FakeTransport()
    val idle   = FakeTransport()
    val (ea, pid) = confirmedEngine(active, BuddyRole.Initiator)
    val (ei, _)   = confirmedEngine(idle, BuddyRole.Initiator)
    for r <- 1 to rounds do
      ea.sendMessage(pid, s"hello$r")
      ea.tick(r)
      ei.tick(r) // idle: never sends
    // Same number of writes, same frame size, same token size — identical observable write shape.
    assert(active.submits.size == rounds && idle.submits.size == rounds)
    assert((active.submits ++ idle.submits).forall(_._2.length == frame.Frame.Size))
    assert((active.submits ++ idle.submits).forall(_._1.length == token.RetrievalToken.Length))
    assert(active.submits.map(s => (s._1.length, s._2.length)) == idle.submits.map(s => (s._1.length, s._2.length)))

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

  test("multiple waiting messages are delivered one per round (uniform fetch, FR-012)"):
    val t = FakeTransport()
    val (alice, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    val (bob, _)        = confirmedEngine(t, BuddyRole.Responder)
    alice.sendMessage(pairId, "m1"); alice.tick(1)
    alice.sendMessage(pairId, "m2"); alice.tick(2)
    // Exactly one retrieve per round ⇒ messages arrive one per round, not all at once.
    bob.tick(3)
    assert(bob.drainEvents().collect { case EngineEvent.MessageReceived(_, txt, _) => txt } == Seq("m1"))
    bob.tick(4)
    assert(bob.drainEvents().collect { case EngineEvent.MessageReceived(_, txt, _) => txt } == Seq("m2"))

  test("active and idle FETCH traces are indistinguishable: one retrieve per round (T041 fetch path)"):
    // An active receiver (messages waiting) and an idle one (none) must issue the SAME number of
    // retrieves — exactly one per round — so an observer can't tell them apart by fetch volume.
    val rounds  = 12
    val activeT = FakeTransport()
    val idleT   = FakeTransport()
    val (active, _) = confirmedEngine(activeT, BuddyRole.Responder)
    val (idle, _)   = confirmedEngine(idleT, BuddyRole.Responder)
    // Pre-stage several messages into the active receiver's store (as the sender would have).
    val sender = Engine(Some(activeT), clientLabel = "x".getBytes)
    val sr = sender.addBuddy(secret("shared"), BuddyRole.Initiator).toOption.get
    sender.confirmBuddy(sr.pairId, matched = true); sender.drainEvents()
    for r <- 1 to 5 do { sender.sendMessage(sr.pairId, s"m$r"); sender.tick(r) }
    activeT.retrieves.clear() // ignore the sender's own reads; measure the receiver only
    var activeDelivered = 0
    for r <- 1 to rounds do
      active.tick(r)
      activeDelivered += active.drainEvents().count(_.isInstanceOf[EngineEvent.MessageReceived])
      idle.tick(r)
    // Exactly one retrieve per round for BOTH — fetch volume reveals nothing about waiting mail.
    assert(activeT.retrieves.size == rounds, "active receiver issues exactly one retrieve per round")
    assert(idleT.retrieves.size == rounds, "idle receiver issues exactly one retrieve per round")
    assert((activeT.retrieves ++ idleT.retrieves).forall(_.length == token.RetrievalToken.Length))
    // Uniformity didn't drop delivery: the staged messages still arrive (one per round).
    assert(activeDelivered == 5, s"all staged messages delivered, got $activeDelivered")
