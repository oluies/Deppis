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

  /** A shared in-memory backend modelling obsd: one token→frame store plus a notify aggregator that
    * CONNECTS `signal`→`fetchDigest` (per round + label tag), so two engines wired to it drive the full
    * stop-and-wait ARQ flow automatically — auto-signal on send, auto-ack on receipt. Round-derived
    * addressing reads the PREVIOUS round's writes (one-round latency), so ticking both engines in any
    * order per round is fine. */
  private final class FakeBackend:
    val store = mutable.Map.empty[String, Array[Byte]]
    private val bits = mutable.Map.empty[(Long, Vector[Byte]), mutable.Set[Int]]
    var rejectSubmit = false
    var writes = 0
    val retrieves = mutable.ArrayBuffer.empty[Vector[Byte]] // every read token, across all clients
    def transport(): RoundTransport = new RoundTransport:
      def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
        writes += 1
        if rejectSubmit then false else { store(hex(token)) = frame; true }
      def retrieve(token: Array[Byte]): Option[Array[Byte]] =
        retrieves += token.toVector; store.remove(hex(token))
      override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
        bits.getOrElseUpdate((roundId, label.toVector), mutable.Set.empty) += bit
      def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
        val out = new Array[Byte](64)
        bits
          .get((roundId, clientLabel.toVector))
          .foreach(_.foreach { b =>
            out(b >> 3) = (out(b >> 3) | (1 << (b & 7))).toByte
          })
        out

  /** Alice (Initiator) + Bob (Responder) over ONE connected backend, each knowing the other's notify
    * label, so the engines auto-signal + auto-ack the ARQ flow. */
  private def connectedPair(): (Engine, Engine, String, FakeBackend) =
    val be = FakeBackend()
    val aLabel = "alice".getBytes; val bLabel = "bob".getBytes
    val alice = Engine(Some(be.transport()), clientLabel = aLabel)
    val pid = alice
      .addBuddy(secret("shared"), BuddyRole.Initiator, peerNotifyLabel = bLabel)
      .toOption
      .get
      .pairId
    alice.confirmBuddy(pid, matched = true); alice.drainEvents()
    val bob = Engine(Some(be.transport()), clientLabel = bLabel)
    bob.addBuddy(secret("shared"), BuddyRole.Responder, peerNotifyLabel = aLabel)
    bob.confirmBuddy(pid, matched = true); bob.drainEvents()
    (alice, bob, pid, be)

  /** Tick both engines through rounds `from..to`, collecting each side's delivered messages. */
  private def converse(a: Engine, b: Engine, from: Long, to: Long): (Seq[String], Seq[String]) =
    val ma = mutable.ArrayBuffer.empty[String]; val mb = mutable.ArrayBuffer.empty[String]
    for r <- from to to do
      a.tick(r); b.tick(r)
      ma ++= a.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      mb ++= b.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    (ma.toSeq, mb.toSeq)

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
    "the engine emits exactly ONE notify signal per round — to the peer while in flight, else a decoy"
  ):
    // One signal per round (uniform volume, FR-012). While a message is in flight it RETRANSMITS each
    // round (advance-on-ack), signaling the PEER; when idle the signal is a DECOY to a per-client void
    // label (NOT Bob's). Either way exactly one same-length signal per round.
    val bobLabel = "bob-agg-label".getBytes
    val t = FakeTransport()
    val alice = Engine(Some(t), clientLabel = "alice".getBytes)
    val pid = alice
      .addBuddy(secret("shared"), BuddyRole.Initiator, peerNotifyLabel = bobLabel)
      .toOption
      .get
      .pairId
    alice.confirmBuddy(pid, matched = true); alice.drainEvents()
    val realTag = NotifyDigest.labelTag(bobLabel).toVector
    // Idle (nothing queued): one DECOY signal per round, never the peer.
    alice.tick(1); alice.tick(2)
    assert(t.signals.map(_._1) == Seq(1L, 2L), "one signal per idle round")
    assert(t.signals.forall(_._2 != realTag), "idle rounds signal a decoy, not the peer")
    assert(t.signals.map(_._2.size).distinct.size == 1, "uniform label length (no size leak)")
    // In flight (queued, unacked here): retransmits each round, signaling the peer every round.
    t.signals.clear()
    alice.sendMessage(pid, "hi")
    alice.tick(3); alice.tick(4)
    assert(t.signals.map(_._2) == Seq(realTag, realTag), "in-flight ⇒ signal the peer each round")
    assert(t.signals(0)._3 == bitOf(pairKeyOf("shared"), 3L), "under round 3's rotated bit")
    // CRITICAL (FR-012, no active-vs-idle size leak): every signal's label is the SAME length, so the
    // sealed-token byte size is identical on real and idle rounds.
    assert(t.signals.map(_._2.size).distinct == Seq(t.signals.head._2.size), "uniform label length")

  test(
    "notify label tag is fixed-width regardless of the peer label's length (no which-buddy size leak)"
  ):
    // Two peers with very different raw label lengths must produce SAME-length signal labels, so the
    // sealed-token size can't reveal which buddy was notified.
    val tShort = FakeTransport(); val tLong = FakeTransport()
    def realSignalLen(t: FakeTransport, peerLabel: Array[Byte]): Int =
      val e = Engine(Some(t), clientLabel = "me".getBytes)
      val pid = e
        .addBuddy(secret("s"), BuddyRole.Initiator, peerNotifyLabel = peerLabel)
        .toOption
        .get
        .pairId
      e.confirmBuddy(pid, matched = true); e.drainEvents()
      e.sendMessage(pid, "x"); e.tick(1)
      t.signals.head._2.size
    assert(realSignalLen(tShort, "b".getBytes) == realSignalLen(tLong, ("y" * 200).getBytes))

  test("a local-only buddy (no peer notify label) still emits one decoy signal per round"):
    // No peerNotifyLabel ⇒ the engine can't notify the peer, but it STILL signals once per round (a
    // decoy) so an unconfigured/local-only client is not distinguishable from a configured one.
    val t = FakeTransport()
    val (bob, _) =
      confirmedEngine(t, BuddyRole.Responder) // confirmedEngine adds with no peer label
    bob.tick(1); bob.tick(2)
    assert(t.signals.size == 2 && t.signals.forall(_._2.nonEmpty), "one decoy signal per round")

  test(
    "ARQ inner header reserves 16 bytes: a message at the reduced cap round-trips; over it is rejected"
  ):
    // The sealed inner block is now [ackSeq(8)][msgSeq(8)][padded message], so the per-message payload
    // shrank by 16 bytes vs. the raw ratchet inner. A message at the new cap delivers intact; one that
    // would have fit the raw inner but not the ARQ-reduced cap is rejected at sendMessage.
    val (alice, bob, pairId, _, tb) = sharedPair()
    val maxMsg = "x" * (DoubleRatchet.InnerSize - 16 - 2) // ARQ header(16) + Frame length prefix(2)
    assert(alice.sendMessage(pairId, maxMsg).isRight)
    alice.tick(1); tb.signalMail(pairKeyOf("shared")); bob.tick(2)
    assert(msgs(bob) == Seq(maxMsg), "a max-length message round-trips through the ARQ inner block")
    assert(
      alice.sendMessage(pairId, "y" * (DoubleRatchet.InnerSize - 2)).isLeft,
      "a message over the ARQ-reduced cap (but within the raw inner) is rejected"
    )

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
    assert(alice.tick(1).toOption.get.carrier, "a rejected submit is reported as a carrier round")
    t.acceptSubmit = true
    assert(!alice.tick(2).toOption.get.carrier, "the successful (re)transmit is a real round")
    // (Under ARQ an unacked message keeps retransmitting under fresh round tokens; idle⇒carrier is
    // covered once a message is acked — see the connected-backend tests.)

  test(
    "multiple queued messages are delivered IN ORDER (stop-and-wait ARQ over the connected backend)"
  ):
    val (alice, bob, pid, _) = connectedPair()
    alice.sendMessage(pid, "m1"); alice.sendMessage(pid, "m2"); alice.sendMessage(pid, "m3")
    val (_, bobMsgs) = converse(alice, bob, 1, 24)
    assert(bobMsgs == Seq("m1", "m2", "m3"), s"in order, got $bobMsgs")

  test(
    "frame content is encrypted: real and cover wire frames are 256B, random, no plaintext (T042)"
  ):
    val plaintext = "the secret meeting time is noon"
    // A sending engine ⇒ a real frame; a separate idle engine ⇒ a cover frame (under ARQ an in-flight
    // head keeps retransmitting, so an idle engine is how you observe a cover write).
    val ts = FakeTransport(); val (es, pid) = confirmedEngine(ts, BuddyRole.Initiator)
    es.sendMessage(pid, plaintext); es.tick(1)
    val realWire = ts.submits(0)._2
    val ti = FakeTransport(); val (ei, _) = confirmedEngine(ti, BuddyRole.Initiator)
    ei.tick(1) // idle ⇒ cover write
    val coverWire = ti.submits(0)._2
    assert(
      realWire.length == frame.Frame.Size && coverWire.length == frame.Frame.Size,
      "both wire frames are 256B"
    )
    // The real frame does NOT contain the plaintext bytes — it's encrypted, not padded plaintext.
    assert(
      !new String(realWire, "ISO-8859-1").contains(plaintext),
      "plaintext must not appear on the wire"
    )
    // The cover frame is NOT all-zero (it's high-entropy random) — byte-indistinguishable from a real
    // frame, not a zero block.
    assert(coverWire.exists(_ != 0), "cover frame must be random (not all-zero)")
    assert(!realWire.sameElements(coverWire))

  test(
    "bidirectional delivery: the responder replies after receiving (initiator-sends-first, ARQ)"
  ):
    val (alice, bob, pid, _) = connectedPair()
    // Initiator sends first; the responder queues its reply but cannot send until it has received.
    assert(bob.sendMessage(pid, "too early") == Right(1))
    alice.sendMessage(pid, "hi bob")
    val (aliceMsgs, bobMsgs) = converse(alice, bob, 1, 20)
    assert(bobMsgs == Seq("hi bob"), s"bob got $bobMsgs")
    assert(aliceMsgs == Seq("too early"), s"alice got $aliceMsgs")
    // A fresh reply each way keeps the ping-pong (and the DH ratchet healing) going.
    alice.sendMessage(pid, "see you"); bob.sendMessage(pid, "hi alice")
    val (aliceMsgs2, bobMsgs2) = converse(alice, bob, 21, 40)
    assert(bobMsgs2 == Seq("see you") && aliceMsgs2 == Seq("hi alice"), s"$aliceMsgs2 / $bobMsgs2")

  test(
    "MULTI-BUDDY: only the active buddy delivers, and no read token recurs (round-derived, FR-014)"
  ):
    // Bob has two confirmed buddies; only B has a sender. B's messages are delivered; A never sends, so
    // A's slot is never even addressed. Read tokens are round-derived ⇒ all distinct (no recurrence).
    val be = FakeBackend()
    val bob = Engine(Some(be.transport()), clientLabel = "bob".getBytes)
    val pidA =
      bob
        .addBuddy(secret("buddy-A"), BuddyRole.Responder, peerNotifyLabel = "A".getBytes)
        .toOption
        .get
        .pairId
    val pidB =
      bob
        .addBuddy(secret("buddy-B"), BuddyRole.Responder, peerNotifyLabel = "B".getBytes)
        .toOption
        .get
        .pairId
    bob.confirmBuddy(pidA, matched = true); bob.confirmBuddy(pidB, matched = true);
    bob.drainEvents()
    val senderB = Engine(Some(be.transport()), clientLabel = "B".getBytes)
    senderB.addBuddy(secret("buddy-B"), BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes)
    senderB.confirmBuddy(pidB, matched = true); senderB.drainEvents()
    for i <- 1 to 4 do senderB.sendMessage(pidB, s"b$i")
    val got = mutable.ArrayBuffer.empty[String]
    for r <- 1L to 30L do
      senderB.tick(r); bob.tick(r)
      got ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    assert(got == Seq("b1", "b2", "b3", "b4"), s"B's messages delivered in order, got $got")
    assert(
      be.retrieves.distinct.size == be.retrieves.size,
      "round-derived ⇒ no read token recurs, even multi-buddy"
    )

  test("two buddies both sending to Bob are both delivered over time — no starvation (T041c edge)"):
    // Bob has two confirmed buddies A and B, EACH with its own sender, both sending concurrently. With
    // one read per round the fairness cursor + ARQ retransmit must deliver BOTH (neither starved).
    val be = FakeBackend()
    val bob = Engine(Some(be.transport()), clientLabel = "bob".getBytes)
    val pidA =
      bob
        .addBuddy(secret("buddy-A"), BuddyRole.Responder, peerNotifyLabel = "A".getBytes)
        .toOption
        .get
        .pairId
    val pidB =
      bob
        .addBuddy(secret("buddy-B"), BuddyRole.Responder, peerNotifyLabel = "B".getBytes)
        .toOption
        .get
        .pairId
    bob.confirmBuddy(pidA, matched = true); bob.confirmBuddy(pidB, matched = true);
    bob.drainEvents()
    val sa = Engine(Some(be.transport()), clientLabel = "A".getBytes)
    sa.addBuddy(secret("buddy-A"), BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes)
    sa.confirmBuddy(pidA, matched = true); sa.drainEvents()
    val sb = Engine(Some(be.transport()), clientLabel = "B".getBytes)
    sb.addBuddy(secret("buddy-B"), BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes)
    sb.confirmBuddy(pidB, matched = true); sb.drainEvents()
    for i <- 1 to 3 do { sa.sendMessage(pidA, s"a$i"); sb.sendMessage(pidB, s"b$i") }
    val got = mutable.ArrayBuffer.empty[String]
    for r <- 1L to 40L do
      sa.tick(r); sb.tick(r); bob.tick(r)
      got ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, txt, _) => txt }
    assert(got.count(_.startsWith("a")) == 3, s"A starved? got $got")
    assert(got.count(_.startsWith("b")) == 3, s"B starved? got $got")
    assert(got.filter(_.startsWith("a")) == Seq("a1", "a2", "a3"), s"A out of order: $got")
    assert(got.filter(_.startsWith("b")) == Seq("b1", "b2", "b3"), s"B out of order: $got")

  test(
    "OFFLINE PEER: a head retransmitted for >MaxSkip rounds still delivers when the peer returns"
  ):
    // The head retransmits every round while unacked, but the cached-wire design does NOT advance the
    // ratchet per round, so a peer offline far longer than MaxSkip (1000) can still decrypt on return.
    // (Pre-fix `encrypt`-per-transmit grew Ns by one per round and stalled permanently past ~1000.)
    val (alice, bob, pid, _) = connectedPair()
    alice.sendMessage(pid, "still here?")
    for r <- 1L to 1500L do
      alice.tick(r) // Alice retransmits 1500 rounds; Bob is OFFLINE (not ticking)
    val got = mutable.ArrayBuffer.empty[String]
    for r <- 1501L to 1520L do
      alice.tick(r); bob.tick(r)
      got ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    assert(got == Seq("still here?"), s"offline-then-online delivery failed, got $got")

  test(
    "SEND FAIRNESS: one engine sending to TWO buddies delivers to both (no head-of-line blocking)"
  ):
    // Without a send-side cursor the first buddy's held head monopolizes the one-write-per-round slot
    // and starves the other; the sendCursor rotation must deliver to both.
    val be = FakeBackend()
    val alice = Engine(Some(be.transport()), clientLabel = "alice".getBytes)
    val pid1 =
      alice
        .addBuddy(secret("s1"), BuddyRole.Initiator, peerNotifyLabel = "b1".getBytes)
        .toOption
        .get
        .pairId
    val pid2 =
      alice
        .addBuddy(secret("s2"), BuddyRole.Initiator, peerNotifyLabel = "b2".getBytes)
        .toOption
        .get
        .pairId
    alice.confirmBuddy(pid1, matched = true); alice.confirmBuddy(pid2, matched = true);
    alice.drainEvents()
    val b1 = Engine(Some(be.transport()), clientLabel = "b1".getBytes)
    b1.addBuddy(secret("s1"), BuddyRole.Responder, peerNotifyLabel = "alice".getBytes)
    b1.confirmBuddy(pid1, matched = true); b1.drainEvents()
    val b2 = Engine(Some(be.transport()), clientLabel = "b2".getBytes)
    b2.addBuddy(secret("s2"), BuddyRole.Responder, peerNotifyLabel = "alice".getBytes)
    b2.confirmBuddy(pid2, matched = true); b2.drainEvents()
    alice.sendMessage(pid1, "to-b1"); alice.sendMessage(pid2, "to-b2")
    val g1 = mutable.ArrayBuffer.empty[String]; val g2 = mutable.ArrayBuffer.empty[String]
    for r <- 1L to 30L do
      alice.tick(r); b1.tick(r); b2.tick(r)
      g1 ++= b1.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      g2 ++= b2.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    assert(g1 == Seq("to-b1"), s"b1 starved? got $g1")
    assert(g2 == Seq("to-b2"), s"b2 starved? got $g2")

  test(
    "RE-ENCRYPT ON ACK ADVANCE: a heavy bidirectional exchange delivers both ways (path-b coverage)"
  ):
    // Each side holds an unacked head while RECEIVING the other's messages, so its highRecv advances and
    // the cached head wire is re-encrypted (the second bounded-Ns path, not exercised by the one-way
    // offline test). Both full streams must still deliver in order — i.e. the gap stayed within MaxSkip.
    val (alice, bob, pid, _) = connectedPair()
    for i <- 1 to 5 do { alice.sendMessage(pid, s"a$i"); bob.sendMessage(pid, s"b$i") }
    val (aGot, bGot) = converse(alice, bob, 1, 80)
    assert(bGot == Seq("a1", "a2", "a3", "a4", "a5"), s"bob got $bGot")
    assert(aGot == Seq("b1", "b2", "b3", "b4", "b5"), s"alice got $aGot")
