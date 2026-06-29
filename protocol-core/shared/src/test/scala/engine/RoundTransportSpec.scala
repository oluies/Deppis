package engine

import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** T032a/T041/T041b: the engine drives the notify/store backend through [[RoundTransport]] with
  * per-buddy notify-before-retrieval (FR-004) and uniform per-round cover traffic on BOTH the send
  * and fetch paths (FR-012). The PING digest carries one bit per buddy; the engine reads EXACTLY the
  * buddy whose bit is set this round, so a real read is always a hit and its token never recurs
  * (FR-014) — for any buddy count. */
class RoundTransportSpec extends AnyFunSuite:

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString
  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")
  private def pairKeyOf(s: String): Array[Byte] = handshake.Handshake.init(secret(s)).pairKey
  // The engine derives the notify bit from the addressing root (the forward-secrecy root split), so a
  // test signaller must too — single source of truth via KeySchedule.addrKey.
  private def bitOf(pairKey: Array[Byte], roundId: Long): Int =
    NotifyDigest.bit(KeySchedule.addrKey(pairKey), roundId)

  /** In-memory store + a 512-bit PING digest, recording the observable submit + fetch traces.
    * Notify is per-round: `signalMail` QUEUES a buddy as having mail, and `fetchDigest(roundId)`
    * computes that buddy's ROUND-ROTATED bit (T041c) into the digest and clears the queue — exactly
    * what the real front does, and matching the engine's per-round derivation, so a signal must be
    * set each round mail should be delivered. Separate transports can share a store. */
  private final class FakeTransport(val store: mutable.Map[String, Array[Byte]] = mutable.Map.empty)
      extends RoundTransport:
    var acceptSubmit: Boolean = true
    private val pendingMail =
      mutable.ArrayBuffer.empty[Array[Byte]] // pairKeys signaled for next fetch
    val submits = mutable.ArrayBuffer.empty[(Array[Byte], Array[Byte])]
    val retrieves = mutable.ArrayBuffer.empty[Array[Byte]]
    // The engine's OUTGOING notify signals (roundId, label, bit) — one per round (FR-012 notify layer).
    val signals = mutable.ArrayBuffer.empty[(Long, Vector[Byte], Int)]

    /** Signal that the buddy with `pairKey` has mail this round (its bit is set at the next fetch). */
    def signalMail(pairKey: Array[Byte]): Unit = pendingMail += pairKey
    override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
      signals += ((roundId, label.toVector, bit))
    def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
      submits += ((token, frame))
      if acceptSubmit then store(hex(token)) = frame
      acceptSubmit
    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
      val out = new Array[Byte](64)
      for pk <- pendingMail do
        val bit = bitOf(pk, roundId); out(bit >> 3) = (out(bit >> 3) | (1 << (bit & 7))).toByte
      pendingMail.clear() // per-round reset
      out
    def retrieve(token: Array[Byte]): Option[Array[Byte]] =
      retrieves += token
      store.remove(hex(token))

  private def confirmedEngine(t: RoundTransport, role: BuddyRole): (Engine, String) =
    val e = Engine(Some(t), clientLabel = "client".getBytes)
    val r = e.addBuddy(secret("shared"), role).toOption.get
    e.confirmBuddy(r.pairId, matched = true); e.drainEvents()
    (e, r.pairId)

  /** Alice (Initiator) + Bob (Responder), each with its own transport over ONE shared store. */
  private def sharedPair(): (Engine, Engine, String, FakeTransport, FakeTransport) =
    val store = mutable.Map.empty[String, Array[Byte]]
    val ta = new FakeTransport(store)
    val tb = new FakeTransport(store)
    val alice = Engine(Some(ta), clientLabel = "alice".getBytes)
    val pairId = alice.addBuddy(secret("shared"), BuddyRole.Initiator).toOption.get.pairId
    alice.confirmBuddy(pairId, matched = true); alice.drainEvents()
    val bob = Engine(Some(tb), clientLabel = "bob".getBytes)
    bob.addBuddy(secret("shared"), BuddyRole.Responder); bob.confirmBuddy(pairId, matched = true);
    bob.drainEvents()
    (alice, bob, pairId, ta, tb)

  private def msgs(e: Engine): Seq[String] =
    e.drainEvents().collect { case EngineEvent.MessageReceived(_, txt, _) => txt }

  test("no transport ⇒ tick emits no delivery events (local-only default)"):
    val e = Engine()
    val r = e.addBuddy(secret("s"), BuddyRole.Initiator).toOption.get
    e.confirmBuddy(r.pairId, matched = true); e.drainEvents()
    assert(e.tick(1).isRight)
    assert(e.drainEvents().isEmpty)

  test("the client privacy label reflects the transport's attestation status (T058)"):
    // A transport that reports a given backend status (the only override; I/O is unused here).
    final class StatusTransport(s: privacy.Privacy.BuildPrivacyStatus) extends RoundTransport:
      def submit(token: Array[Byte], frame: Array[Byte]): Boolean = true
      def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] = new Array[Byte](64)
      def retrieve(token: Array[Byte]): Option[Array[Byte]] = None
      override def privacyStatus: privacy.Privacy.BuildPrivacyStatus = s
    import privacy.Privacy
    // Local-only (no transport) ⇒ dev label.
    assert(!Engine().privacyStatus.metadataPrivate)
    assert(Engine().privacyStatus.label == Privacy.DevLabel)
    // A real, ATTESTED enclave-target backend ⇒ METADATA PRIVATE.
    val attested = Engine(
      Some(
        StatusTransport(
          Privacy.BuildPrivacyStatus(Privacy.Backend.EnclaveTarget, attestationPassed = true)
        )
      )
    )
    assert(
      attested.privacyStatus.metadataPrivate && attested.privacyStatus.label == Privacy.PrivateLabel
    )
    // An UNATTESTED enclave-target backend ⇒ stays dev (the gate never promotes without attestation).
    val unattested = Engine(
      Some(
        StatusTransport(
          Privacy.BuildPrivacyStatus(Privacy.Backend.EnclaveTarget, attestationPassed = false)
        )
      )
    )
    assert(
      !unattested.privacyStatus.metadataPrivate && unattested.privacyStatus.label == Privacy.DevLabel
    )

  test("tick emits notified when the buddy's digest bit is set (FR-004)"):
    val t = FakeTransport()
    val (bob, _) = confirmedEngine(t, BuddyRole.Responder)
    t.signalMail(pairKeyOf("shared"))
    bob.tick(1)
    assert(bob.drainEvents().contains(EngineEvent.Notified(1)))

  test("tick emits no notified when no bit is set"):
    val t = FakeTransport()
    val (bob, _) = confirmedEngine(t, BuddyRole.Responder)
    bob.tick(1)
    assert(!bob.drainEvents().exists(_.isInstanceOf[EngineEvent.Notified]))

  test(
    "the engine emits exactly ONE notify signal per round — real to the peer, else a decoy (FR-012)"
  ):
    // Alice knows Bob's notify label (set at pairing), so a real send signals (bobLabel, round-rotated
    // bit); an idle round signals a DECOY to a per-client void label (NOT Bob's). Uniform one-signal-
    // per-round hides active-vs-idle at the notify layer from the untrusted host.
    val bobLabel = "bob-agg-label".getBytes
    val t = FakeTransport()
    val alice = Engine(Some(t), clientLabel = "alice".getBytes)
    val pid = alice
      .addBuddy(secret("shared"), BuddyRole.Initiator, peerNotifyLabel = bobLabel)
      .toOption
      .get
      .pairId
    alice.confirmBuddy(pid, matched = true); alice.drainEvents()
    alice.sendMessage(pid, "hi")
    alice.tick(1) // real send ⇒ signal Bob
    alice.tick(2) // idle ⇒ decoy
    alice.tick(3) // idle ⇒ decoy
    assert(t.signals.map(_._1) == Seq(1L, 2L, 3L), "exactly one signal per round, in order")
    // Round 1 is a real signal to Bob's label under the pair's round-1 rotated bit.
    assert(t.signals(0)._2 == bobLabel.toVector, "real send signals the peer's label")
    assert(t.signals(0)._3 == bitOf(pairKeyOf("shared"), 1L), "under the pair's round-rotated bit")
    // Idle rounds signal a DECOY — never the peer's label — so volume is uniform but no peer is notified.
    assert(t.signals(1)._2 != bobLabel.toVector && t.signals(2)._2 != bobLabel.toVector, "decoys")

  test("a local-only buddy (no peer notify label) still emits one decoy signal per round"):
    // No peerNotifyLabel ⇒ the engine can't notify the peer, but it STILL signals once per round (a
    // decoy) so an unconfigured/local-only client is not distinguishable from a configured one.
    val t = FakeTransport()
    val (bob, _) =
      confirmedEngine(t, BuddyRole.Responder) // confirmedEngine adds with no peer label
    bob.tick(1); bob.tick(2)
    assert(t.signals.size == 2 && t.signals.forall(_._2.nonEmpty), "one decoy signal per round")

  test("a message submitted by the sender is retrieved + surfaced by the receiver"):
    val (alice, bob, pairId, _, tb) = sharedPair()
    assert(alice.sendMessage(pairId, "meet at noon") == Right(1))
    alice.tick(1)
    tb.signalMail(pairKeyOf("shared"))
    bob.tick(2)
    assert(msgs(bob) == Seq("meet at noon"))

  test("notify is emitted BEFORE the retrieved message (notify-before-retrieval order)"):
    val (alice, bob, pairId, _, tb) = sharedPair()
    alice.sendMessage(pairId, "hi"); alice.tick(1)
    tb.signalMail(pairKeyOf("shared"))
    bob.tick(2)
    val evs = bob.drainEvents()
    val ni = evs.indexWhere(_.isInstanceOf[EngineEvent.Notified])
    val mi = evs.indexWhere(_.isInstanceOf[EngineEvent.MessageReceived])
    assert(ni >= 0 && mi >= 0 && ni < mi, s"expected notified before messageReceived, got $evs")

  test("single-use: the same message is not delivered twice"):
    val (alice, bob, pairId, _, tb) = sharedPair()
    alice.sendMessage(pairId, "once"); alice.tick(1)
    tb.signalMail(pairKeyOf("shared")); bob.tick(2)
    assert(msgs(bob) == Seq("once"))
    bob.tick(3) // no signal this round ⇒ cover read, nothing redelivered
    assert(msgs(bob).isEmpty)

  test("a failed submit keeps the frame queued and retries it next round (no message loss)"):
    val (alice, bob, pairId, ta, tb) = sharedPair()
    alice.sendMessage(pairId, "important")
    ta.acceptSubmit = false
    alice.tick(1)
    assert(ta.store.isEmpty)
    bob.tick(2)
    assert(msgs(bob).isEmpty)
    ta.acceptSubmit = true
    alice.tick(3)
    tb.signalMail(pairKeyOf("shared")); bob.tick(4)
    assert(msgs(bob) == Seq("important"))

  test("cover traffic: every round makes exactly one store write whether active or idle"):
    val t = FakeTransport()
    val (e, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    for r <- 1 to 5 do
      if r % 2 == 1 then e.sendMessage(pairId, s"msg$r")
      e.tick(r)
    assert(t.submits.size == 5)
    assert(e.internalAnomalyCount == 0)

  test(
    "one store write per round holds under a transient submit failure (actual store, not attempts)"
  ):
    val t = FakeTransport()
    val (e, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    e.tick(1)
    assert(t.store.size == 1)
    t.acceptSubmit = false
    e.tick(2)
    assert(t.submits.size == 2 && t.store.size == 1)
    e.sendMessage(pairId, "later"); e.tick(3)
    assert(t.submits.size == 3 && t.store.size == 1)
    t.acceptSubmit = true; e.tick(4)
    assert(t.store.size == 2)

  test("active and idle STORE-WRITE traces are indistinguishable (T041 send path)"):
    val rounds = 20
    val active = FakeTransport(); val idle = FakeTransport()
    val (ea, pid) = confirmedEngine(active, BuddyRole.Initiator)
    val (ei, _) = confirmedEngine(idle, BuddyRole.Initiator)
    for r <- 1 to rounds do
      ea.sendMessage(pid, s"hello$r"); ea.tick(r); ei.tick(r)
    assert(active.submits.size == rounds && idle.submits.size == rounds)
    assert((active.submits ++ idle.submits).forall(_._2.length == frame.Frame.Size))
    assert((active.submits ++ idle.submits).forall(_._1.length == token.RetrievalToken.Length))

  test(
    "the carrier flag reflects whether a real frame was actually submitted (fail+retry uniform)"
  ):
    val t = FakeTransport()
    val (alice, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    alice.sendMessage(pairId, "x")
    t.acceptSubmit = false
    assert(alice.tick(1).toOption.get.carrier)
    t.acceptSubmit = true
    assert(!alice.tick(2).toOption.get.carrier)
    assert(alice.tick(3).toOption.get.carrier)

  test("multiple waiting messages are delivered one per round (uniform fetch, FR-012)"):
    val (alice, bob, pairId, _, tb) = sharedPair()
    alice.sendMessage(pairId, "m1"); alice.tick(1)
    alice.sendMessage(pairId, "m2"); alice.tick(2)
    tb.signalMail(pairKeyOf("shared")); bob.tick(3); assert(msgs(bob) == Seq("m1"))
    tb.signalMail(pairKeyOf("shared")); bob.tick(4); assert(msgs(bob) == Seq("m2"))

  test(
    "frame content is encrypted: real and carrier wire frames are 256B, random, no plaintext (T042)"
  ):
    val t = FakeTransport()
    val (e, pairId) = confirmedEngine(t, BuddyRole.Initiator)
    val plaintext = "the secret meeting time is noon"
    e.sendMessage(pairId, plaintext)
    e.tick(1) // real send (encrypted)
    e.tick(2) // idle ⇒ carrier (encrypted)
    val realWire = t.submits(0)._2
    val carrierWire = t.submits(1)._2
    assert(
      realWire.length == frame.Frame.Size && carrierWire.length == frame.Frame.Size,
      "both wire frames are 256B"
    )
    // The real frame does NOT contain the plaintext bytes — it's encrypted, not padded plaintext.
    assert(
      !new String(realWire, "ISO-8859-1").contains(plaintext),
      "plaintext must not appear on the wire"
    )
    // The carrier is NOT all-zero (it's an encryption of zeros under a random key) — so it is
    // byte-indistinguishable from a real frame (both high-entropy 256B blobs), not a zero block.
    assert(carrierWire.exists(_ != 0), "carrier frame must be encrypted (not all-zero)")
    assert(!realWire.sameElements(carrierWire))

  test("bidirectional delivery: the responder replies after receiving (DH-ratchet ping-pong E2E)"):
    val (alice, bob, pairId, ta, tb) = sharedPair()
    // Initiator sends first; the responder cannot send until it has received (initiator-sends-first).
    assert(bob.sendMessage(pairId, "too early") == Right(1)) // queues, but bob can't send it yet
    // Bob can't send before receiving ⇒ a CARRIER round (its one store write is a cover frame, so the
    // trace is uniform); the message is held, not lost.
    assert(
      bob.tick(0).toOption.exists(_.carrier),
      "responder's held message yields a carrier round"
    )
    // Alice → Bob.
    alice.sendMessage(pairId, "hi bob"); alice.tick(1)
    tb.signalMail(pairKeyOf("shared")); bob.tick(2)
    assert(msgs(bob) == Seq("hi bob"))
    // Now bob's receiving DH step has opened a sending chain — its held reply now flows back.
    bob.tick(3)
    ta.signalMail(pairKeyOf("shared")); alice.tick(4)
    assert(msgs(alice) == Seq("too early"))
    // A fresh reply both ways keeps the ping-pong (and the DH ratchet healing) going.
    bob.sendMessage(pairId, "hi alice"); bob.tick(5)
    ta.signalMail(pairKeyOf("shared")); alice.tick(6)
    assert(msgs(alice) == Seq("hi alice"))
    alice.sendMessage(pairId, "see you"); alice.tick(7)
    tb.signalMail(pairKeyOf("shared")); bob.tick(8)
    assert(msgs(bob) == Seq("see you"))

  test("MULTI-BUDDY fetch is non-recurrent: read exactly the signaled buddy (T041b, FR-014)"):
    // Bob has two confirmed buddies A and B. Only B is sending. Each round, the digest signals B's
    // bit (B has mail) and never A's. Bob reads B's (advancing, fresh) real token on signaled rounds
    // and a fresh cover token otherwise — A's frozen token is NEVER read, so NO token recurs even
    // with multiple buddies (the recurrence the previous round-robin design left open).
    val store = mutable.Map.empty[String, Array[Byte]]
    val tb = new FakeTransport(store)
    val tsB = new FakeTransport(store) // B's sender, shares the store
    val bob = Engine(Some(tb), clientLabel = "bob".getBytes)
    val pidA = handshake.Handshake.init(secret("buddy-A")).pairId
    val pidB = handshake.Handshake.init(secret("buddy-B")).pairId
    bob.addBuddy(secret("buddy-A"), BuddyRole.Responder); bob.confirmBuddy(pidA, matched = true)
    bob.addBuddy(secret("buddy-B"), BuddyRole.Responder); bob.confirmBuddy(pidB, matched = true)
    bob.drainEvents()
    val senderB = Engine(Some(tsB), clientLabel = "B".getBytes)
    senderB.addBuddy(secret("buddy-B"), BuddyRole.Initiator);
    senderB.confirmBuddy(pidB, matched = true); senderB.drainEvents()
    for r <- 1 to 5 do { senderB.sendMessage(pidB, s"b$r"); senderB.tick(r) }
    tb.retrieves.clear()

    val rounds = 12
    var delivered = 0
    for r <- 1 to rounds do
      // B re-signals every round until all its mail is delivered; A never signals. Under T041c a round
      // where A's and B's ROTATED bits collide is ambiguous, so B defers to the next round (where
      // rotation separates them) — hence re-signal-until-delivered rather than a fixed 5-round window.
      if delivered < 5 then tb.signalMail(pairKeyOf("buddy-B"))
      bob.tick(r)
      delivered += bob.drainEvents().count(_.isInstanceOf[EngineEvent.MessageReceived])
    assert(tb.retrieves.size == rounds, "one read per round")
    assert(tb.retrieves.map(hex).toSet.size == rounds, "NO read token recurs, even multi-buddy")
    assert(delivered == 5, s"all of B's messages delivered, got $delivered")

  test(
    "two buddies signaling the SAME round are both served over time (no starvation, T041c edge)"
  ):
    // A and B each have several messages and BOTH signal every round. With one read/round, the
    // fairness cursor must rotate so NEITHER (regardless of pairId order) is starved.
    val store = mutable.Map.empty[String, Array[Byte]]
    val tb = new FakeTransport(store)
    val tsA = new FakeTransport(store); val tsB = new FakeTransport(store)
    val bob = Engine(Some(tb), clientLabel = "bob".getBytes)
    val pidA = handshake.Handshake.init(secret("buddy-A")).pairId
    val pidB = handshake.Handshake.init(secret("buddy-B")).pairId
    bob.addBuddy(secret("buddy-A"), BuddyRole.Responder); bob.confirmBuddy(pidA, matched = true)
    bob.addBuddy(secret("buddy-B"), BuddyRole.Responder); bob.confirmBuddy(pidB, matched = true)
    bob.drainEvents()
    val sa = Engine(Some(tsA), clientLabel = "A".getBytes)
    sa.addBuddy(secret("buddy-A"), BuddyRole.Initiator); sa.confirmBuddy(pidA, matched = true);
    sa.drainEvents()
    val sb = Engine(Some(tsB), clientLabel = "B".getBytes)
    sb.addBuddy(secret("buddy-B"), BuddyRole.Initiator); sb.confirmBuddy(pidB, matched = true);
    sb.drainEvents()
    for r <- 1 to 3 do {
      sa.sendMessage(pidA, s"a$r"); sa.tick(r); sb.sendMessage(pidB, s"b$r"); sb.tick(r)
    }

    val received = mutable.ArrayBuffer.empty[String]
    for r <- 1 to 12 do
      tb.signalMail(pairKeyOf("buddy-A")); tb.signalMail(pairKeyOf("buddy-B")) // BOTH signal
      bob.tick(r)
      received ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, txt, _) => txt }
    // Both buddies fully delivered — neither starved — and (distinct messages) all 6 arrived.
    assert(received.count(_.startsWith("a")) == 3, s"A starved? got $received")
    assert(received.count(_.startsWith("b")) == 3, s"B starved? got $received")
