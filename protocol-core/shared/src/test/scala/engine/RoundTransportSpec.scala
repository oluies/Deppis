package engine

import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** T032a/T041: the engine drives the notify/store backend through [[RoundTransport]] with
  * notify-before-retrieval (FR-004) and uniform per-round cover traffic on BOTH the send and fetch
  * paths (FR-012). A real read happens only when the backend signals mail this round, so a real
  * expected token is read at most once (non-recurrent, FR-014); otherwise a fresh cover read.
  *
  * Tests model an ACCURATE notify: `mail` is set true exactly when a message is present to retrieve
  * (this is what the PING/PONG protocol guarantees — a signal accompanies a successful store write). */
class RoundTransportSpec extends AnyFunSuite:

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString
  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")

  /** In-memory store + a controllable "mail waiting" flag, recording the observable submit + fetch
    * traces. Separate transports can share one `store` map so a sender's write reaches a receiver. */
  private final class FakeTransport(val store: mutable.Map[String, Array[Byte]] = mutable.Map.empty)
      extends RoundTransport:
    var mail: Boolean         = false
    var acceptSubmit: Boolean = true
    val submits   = mutable.ArrayBuffer.empty[(Array[Byte], Array[Byte])]
    val retrieves = mutable.ArrayBuffer.empty[Array[Byte]]
    def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
      submits += ((token, frame))
      if acceptSubmit then store(hex(token)) = frame
      acceptSubmit
    def mailWaiting(roundId: Long, clientLabel: Array[Byte]): Boolean = mail
    def retrieve(token: Array[Byte]): Option[Array[Byte]] =
      retrieves += token
      store.remove(hex(token))

  /** One confirmed buddy on an engine with its own transport + role. */
  private def confirmedEngine(t: RoundTransport, role: BuddyRole): (Engine, String) =
    val e = Engine(Some(t), clientLabel = "client".getBytes)
    val r = e.addBuddy(secret("shared"), role).toOption.get
    e.confirmBuddy(r.pairId, matched = true)
    e.drainEvents()
    (e, r.pairId)

  /** Alice (Initiator) + Bob (Responder), each with its own transport over ONE shared store, both
    * confirmed on the same pair (same secret ⇒ same pairId). */
  private def sharedPair(): (Engine, Engine, String, FakeTransport, FakeTransport) =
    val store = mutable.Map.empty[String, Array[Byte]]
    val ta = new FakeTransport(store)
    val tb = new FakeTransport(store)
    val alice = Engine(Some(ta), clientLabel = "alice".getBytes)
    val pairId = alice.addBuddy(secret("shared"), BuddyRole.Initiator).toOption.get.pairId
    alice.confirmBuddy(pairId, matched = true); alice.drainEvents()
    val bob = Engine(Some(tb), clientLabel = "bob".getBytes)
    bob.addBuddy(secret("shared"), BuddyRole.Responder); bob.confirmBuddy(pairId, matched = true); bob.drainEvents()
    (alice, bob, pairId, ta, tb)

  private def msgs(e: Engine): Seq[String] =
    e.drainEvents().collect { case EngineEvent.MessageReceived(_, txt, _) => txt }

  test("no transport ⇒ tick emits no delivery events (local-only default)"):
    val e = Engine()
    val r = e.addBuddy(secret("s"), BuddyRole.Initiator).toOption.get
    e.confirmBuddy(r.pairId, matched = true); e.drainEvents()
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
    bob.tick(1)
    assert(!bob.drainEvents().exists(_.isInstanceOf[EngineEvent.Notified]))

  test("a message submitted by the sender is retrieved + surfaced by the receiver"):
    val (alice, bob, pairId, _, tb) = sharedPair()
    assert(alice.sendMessage(pairId, "meet at noon") == Right(1))
    alice.tick(1)              // Alice writes the frame to the shared store
    tb.mail = true             // Bob is notified this round
    bob.tick(2)
    assert(msgs(bob) == Seq("meet at noon"))

  test("notify is emitted BEFORE the retrieved message (notify-before-retrieval order)"):
    val (alice, bob, pairId, _, tb) = sharedPair()
    alice.sendMessage(pairId, "hi"); alice.tick(1)
    tb.mail = true
    bob.tick(2)
    val evs = bob.drainEvents()
    val ni  = evs.indexWhere(_.isInstanceOf[EngineEvent.Notified])
    val mi  = evs.indexWhere(_.isInstanceOf[EngineEvent.MessageReceived])
    assert(ni >= 0 && mi >= 0 && ni < mi, s"expected notified before messageReceived, got $evs")

  test("single-use: the same message is not delivered twice"):
    val (alice, bob, pairId, _, tb) = sharedPair()
    alice.sendMessage(pairId, "once"); alice.tick(1)
    tb.mail = true
    bob.tick(2)
    assert(msgs(bob) == Seq("once"))
    bob.tick(3) // still notified but the slot is consumed (counter advanced)
    assert(msgs(bob).isEmpty)

  test("a failed submit keeps the frame queued and retries it next round (no message loss)"):
    val (alice, bob, pairId, ta, tb) = sharedPair()
    alice.sendMessage(pairId, "important")
    ta.acceptSubmit = false
    alice.tick(1)              // submit fails → nothing stored, frame stays queued
    assert(ta.store.isEmpty)
    bob.tick(2)                // not notified (nothing was sent) ⇒ cover read
    assert(msgs(bob).isEmpty)
    ta.acceptSubmit = true
    alice.tick(3)              // retry succeeds
    tb.mail = true             // now Bob is notified
    bob.tick(4)
    assert(msgs(bob) == Seq("important"))

  test("cover traffic: every round makes exactly one store write whether active or idle"):
    val t = FakeTransport()
    val (e, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    for r <- 1 to 5 do
      if r % 2 == 1 then e.sendMessage(pairId, s"msg$r")
      e.tick(r)
    assert(t.submits.size == 5, "exactly one store write per round (no missing/extra writes)")
    assert(e.internalAnomalyCount == 0, "no internal invariant breaks in normal operation")

  test("one store write per round holds under a transient submit failure (actual store, not attempts)"):
    val t = FakeTransport()
    val (e, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    e.tick(1)
    assert(t.store.size == 1, "an idle round writes one cover frame")
    t.acceptSubmit = false
    e.tick(2)
    assert(t.submits.size == 2, "still exactly one write attempt this round")
    assert(t.store.size == 1, "the failed cover write does not land — and is not silently doubled")
    e.sendMessage(pairId, "later"); e.tick(3)
    assert(t.submits.size == 3 && t.store.size == 1)
    t.acceptSubmit = true; e.tick(4)
    assert(t.store.size == 2, "the retried real frame now lands")

  test("active and idle STORE-WRITE traces are indistinguishable (T041 send path)"):
    val rounds = 20
    val active = FakeTransport()
    val idle   = FakeTransport()
    val (ea, pid) = confirmedEngine(active, BuddyRole.Initiator)
    val (ei, _)   = confirmedEngine(idle, BuddyRole.Initiator)
    for r <- 1 to rounds do
      ea.sendMessage(pid, s"hello$r"); ea.tick(r)
      ei.tick(r)
    assert(active.submits.size == rounds && idle.submits.size == rounds)
    assert((active.submits ++ idle.submits).forall(_._2.length == frame.Frame.Size))
    assert((active.submits ++ idle.submits).forall(_._1.length == token.RetrievalToken.Length))
    assert(active.submits.map(s => (s._1.length, s._2.length)) == idle.submits.map(s => (s._1.length, s._2.length)))

  test("the carrier flag reflects whether a real frame was actually submitted (fail+retry uniform)"):
    val t = FakeTransport()
    val (alice, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    alice.sendMessage(pairId, "x")
    t.acceptSubmit = false
    assert(alice.tick(1).toOption.get.carrier, "a failed send reports as a carrier round")
    t.acceptSubmit = true
    assert(!alice.tick(2).toOption.get.carrier, "a successful send reports a real round")
    assert(alice.tick(3).toOption.get.carrier, "an empty round is a carrier")

  test("multiple waiting messages are delivered one per round (uniform fetch, FR-012)"):
    val (alice, bob, pairId, _, tb) = sharedPair()
    alice.sendMessage(pairId, "m1"); alice.tick(1)
    alice.sendMessage(pairId, "m2"); alice.tick(2)
    tb.mail = true // notified each receiving round (a message is present)
    bob.tick(3); assert(msgs(bob) == Seq("m1"))
    bob.tick(4); assert(msgs(bob) == Seq("m2"))

  test("SINGLE-BUDDY fetch trace is non-recurrent and identical for active vs idle (T041, FR-014)"):
    // Active receiver: notified on each round a message is present, reading a real (advancing) token.
    // Idle receiver: never notified, reading a fresh cover token each round. BOTH issue exactly one
    // read per round and — crucially — NO read token recurs, so an observer of the token stream can't
    // tell active from idle (closes the fixed-token-poll recurrence distinguisher). Holds for a single
    // buddy; the multi-buddy case is the next test (recurrence remains until per-buddy notify, T041b).
    val store = mutable.Map.empty[String, Array[Byte]]
    val senderT = new FakeTransport(store)
    val activeT = new FakeTransport(store)
    val idleT   = new FakeTransport()
    val sender = Engine(Some(senderT), clientLabel = "s".getBytes)
    val pid = sender.addBuddy(secret("shared"), BuddyRole.Initiator).toOption.get.pairId
    sender.confirmBuddy(pid, matched = true); sender.drainEvents()
    val active = Engine(Some(activeT), clientLabel = "a".getBytes)
    active.addBuddy(secret("shared"), BuddyRole.Responder); active.confirmBuddy(pid, matched = true); active.drainEvents()
    val (idle, _) = confirmedEngine(idleT, BuddyRole.Responder)
    // Sender stages 5 messages (rounds 1..5).
    for r <- 1 to 5 do { sender.sendMessage(pid, s"m$r"); sender.tick(r) }

    val rounds = 12
    var delivered = 0
    for r <- 1 to rounds do
      activeT.mail = r <= 5 // notified exactly while a staged message is present
      active.tick(r)
      delivered += active.drainEvents().count(_.isInstanceOf[EngineEvent.MessageReceived])
      idle.tick(r) // idleT.mail stays false
    // One read per round each.
    assert(activeT.retrieves.size == rounds && idleT.retrieves.size == rounds)
    // No token recurs — the read stream is fresh every round for BOTH (the recurrence distinguisher).
    def distinct(ts: collection.Seq[Array[Byte]]) = ts.map(hex).toSet.size == ts.size
    assert(distinct(activeT.retrieves), "active read tokens must be non-recurrent")
    assert(distinct(idleT.retrieves), "idle read tokens must be non-recurrent")
    // …and delivery still works.
    assert(delivered == 5, s"all staged messages delivered, got $delivered")

  test("MULTI-BUDDY fetch keeps one read per round, but token non-recurrence is NOT yet held (T041b)"):
    // Documents the known limitation: with ≥2 confirmed buddies and a per-CLIENT notify, the
    // round-robin cursor can land on a buddy with no mail and re-read its frozen token. The COUNT
    // stays uniform (one read/round) — what's NOT yet uniform is token recurrence, which needs
    // per-buddy notify (T041b). This test pins the current behavior so a future fix is visible.
    val t = FakeTransport()
    val bob = Engine(Some(t), clientLabel = "bob".getBytes)
    bob.addBuddy(secret("buddy-A"), BuddyRole.Responder)
    bob.addBuddy(secret("buddy-B"), BuddyRole.Responder)
    bob.confirmBuddy(handshake.Handshake.init(secret("buddy-A")).pairId, matched = true)
    bob.confirmBuddy(handshake.Handshake.init(secret("buddy-B")).pairId, matched = true)
    bob.drainEvents()
    val rounds = 10
    t.mail = true // notified every round (per-client), but the cursor alternates A/B with no mail
    for r <- 1 to rounds do bob.tick(r)
    assert(t.retrieves.size == rounds, "COUNT uniformity holds: exactly one read per round")
    // Token non-recurrence does NOT yet hold for multi-buddy (the limitation T041b closes). With 2
    // confirmed buddies, no queued mail, and the floorMod round-robin, every notified round reads one
    // of exactly TWO frozen recvCounter=0 tokens (alternating A,B,A,B,…). Pin that exact value so any
    // change — partial fix or regression — trips the assertion, not just a full fix.
    val distinctTokens = t.retrieves.map(hex).toSet.size
    assert(distinctTokens == 2, s"pinned multi-buddy recurrence: 2 frozen tokens (pending T041b), got $distinctTokens")
