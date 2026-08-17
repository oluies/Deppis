package engine

import org.scalatest.funsuite.AnyFunSuite

import scala.collection.mutable

/** The FRAME-UNIFORMITY INVARIANT that `unlinkability.spthy`'s result rests on — asserted on BOTH the
  * JVM and Scala.js builds (this file lives in `crosstest`, wired into both
  * `Test / unmanagedSourceDirectories`; see build.sbt).
  *
  * ==Why this file exists (design/continuous-pq-ratchet.md §5 / §9 Q3)==
  * Phase 5's formal analysis records an honest limit: Tamarin has no notion of length, timing or
  * volume, so `unlinkability.spthy` STRUCTURALLY cannot express the 256-byte size uniformity its
  * argument depends on. Grep that model for `256`, `size` or `uniform` and there are no hits — the
  * uniformity is not a weak assumption in the model, it is an assumption OUTSIDE the model. The
  * machine-checked observational equivalence says "given frames the adversary cannot tell apart,
  * the traces are equivalent"; whether the frames really are indistinguishable is a property of
  * THIS code, and no prover output covers it.
  *
  * That makes the invariant load-bearing and unproven, which is the §9 Q3 residual. It cannot be
  * closed by a test — a test is not a proof, and nothing here upgrades Q3 from "argued" to
  * "verified". What a test CAN do is stop the assumption drifting away from the code silently, and
  * that is all this file claims.
  *
  * ==What was already covered, and the hole this fills==
  * The invariant was already asserted on the JVM: `RoundTransportSpec` ("cover traffic: every round
  * makes exactly one store write whether active or idle", "active and idle STORE-WRITE traces match
  * in SHAPE", one-signal-per-round with uniform label length) and `AnonymitySpec` (shape uniformity
  * across the N "which buddy is active" worlds). Both live in `shared/src/test`, which is JVM-ONLY.
  *
  * The engine that runs in a browser and on iOS is the SCALA.JS build of this same source. Nothing
  * asserted the invariant there. A platform-specific regression — a divergent cover path, a
  * different padding result, a JS `Byte` width bug in a token — would have broken uniformity on the
  * clients that actually face an untrusted store, while CI stayed green on the JVM. This spec is
  * cross-compiled precisely so that cannot happen.
  *
  * ==Honest scope (Constitution IV)==
  * Green here is NOT an unlinkability claim and changes no label; `DEV, NO METADATA PRIVACY` stands.
  * These are STRUCTURAL checks — counts, sizes, and the absence of a constant byte offset. They
  * would catch a plaintext tag, a length field, a size divergence, or a missing cover write. They do
  * not and cannot establish that ciphertext is indistinguishable from random: that rests on the AEAD
  * (`RoundTransportSpec`/T042), not on anything measurable here. Nor does anything here address
  * TIMING or VOLUME over time, the other half of Q3. */
class FrameUniformityCrossSpec extends AnyFunSuite:

  private val Rounds = 40

  /** The shared backend state. BOTH the store map and the notify-bit map must be shared by the two
    * sides' recorders: an earlier revision gave each `Recorder` its own `bits`, so neither engine
    * ever saw the other's signal, no mail was ever served, and the "chatting" world was silently as
    * idle as the idle one — every count assertion still passed. The rekey test is what caught it (no
    * content steps ⇒ no fold), which is why that test earns its place beyond duplicating
    * `PqRekeyCrossSpec`: here it doubles as the anti-vacuity guard for the whole file. */
  private final class Fabric:
    val store = mutable.Map.empty[String, Array[Byte]]
    val bits = mutable.Map.empty[(Long, Vector[Byte]), mutable.Set[Int]]

  /** Records the store host's ENTIRE observable: every write, every read token, every notify signal,
    * in order. */
  private final class Recorder(fabric: Fabric) extends RoundTransport:
    private val store = fabric.store
    private val bits = fabric.bits
    val writes = mutable.ArrayBuffer.empty[(Array[Byte], Array[Byte])]
    val reads = mutable.ArrayBuffer.empty[Array[Byte]]
    val signals = mutable.ArrayBuffer.empty[(Long, Array[Byte], Int)]

    def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
      writes += ((token.clone(), frame.clone()))
      store(PqTestKit.hex(token)) = frame
      true

    def retrieve(token: Array[Byte]): Option[Array[Byte]] =
      reads += token.clone()
      store.remove(PqTestKit.hex(token))

    override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
      signals += ((roundId, label.clone(), bit))
      bits.getOrElseUpdate((roundId, label.toVector), mutable.Set.empty) += bit

    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
      val out = new Array[Byte](64)
      bits
        .get((roundId, clientLabel.toVector))
        .foreach(_.foreach(b => out(b >> 3) = (out(b >> 3) | (1 << (b & 7))).toByte))
      out

  /** A confirmed classical pairing over one store, with both sides' observables recorded. */
  private def world(): (Engine, Engine, Recorder, Recorder, String) =
    val fabric = Fabric()
    val ra = Recorder(fabric)
    val rb = Recorder(fabric)
    val alice = Engine(Some(ra), clientLabel = "alice".getBytes("UTF-8"))
    val bob = Engine(Some(rb), clientLabel = "bob".getBytes("UTF-8"))
    val oob = "oob-shared-secret".getBytes("UTF-8")
    val a = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes("UTF-8"))
    val b = bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = "alice".getBytes("UTF-8"))
    val ar = a.toOption.get
    val br = b.toOption.get
    alice.confirmBuddy(ar.pairId, matched = true).toOption.get
    bob.confirmBuddy(br.pairId, matched = true).toOption.get
    alice.drainEvents(); bob.drainEvents()
    (alice, bob, ra, rb, ar.pairId)

  /** Drive `rounds`; `chatting` decides whether real traffic is queued. Returns both recorders and
    * the number of messages actually DELIVERED, so every caller can check it was not measuring two
    * idle engines (see [[Fabric]]). */
  private def drive(rounds: Int, chatting: Boolean): (Recorder, Recorder, Int) =
    val (alice, bob, ra, rb, pid) = world()
    var delivered = 0
    for r <- 1 to rounds do
      if chatting then
        alice.sendMessage(pid, s"a$r"): Unit
        bob.sendMessage(pid, s"b$r"): Unit
      alice.tick(r.toLong): Unit
      bob.tick(r.toLong): Unit
      delivered += alice.drainEvents().count(_.isInstanceOf[EngineEvent.MessageReceived])
      delivered += bob.drainEvents().count(_.isInstanceOf[EngineEvent.MessageReceived])
    (ra, rb, delivered)

  // ===================================================== the per-round budget (FR-012, ARCHITECTURE §6)

  test("EVERY round is exactly one store write and one store read, chatting or idle"):
    // The headline FR-012 claim, stated as a per-round budget rather than a total: a total can be
    // right while individual rounds burst and go silent, which is exactly the pattern a volume
    // observer would read.
    for chatting <- Seq(true, false) do
      val (ra, rb, _) = drive(Rounds, chatting)
      for (who, rec) <- Seq("initiator" -> ra, "responder" -> rb) do
        assert(
          rec.writes.size == Rounds,
          s"$who (chatting=$chatting) wrote ${rec.writes.size} frames in $Rounds rounds"
        )
        assert(
          rec.reads.size == Rounds,
          s"$who (chatting=$chatting) read ${rec.reads.size} times in $Rounds rounds"
        )
        assert(
          rec.signals.size == Rounds,
          s"$who (chatting=$chatting) sent ${rec.signals.size} signals in $Rounds rounds"
        )

  test("every frame is exactly 256 bytes and every token full length, chatting or idle"):
    for chatting <- Seq(true, false) do
      val (ra, rb, _) = drive(Rounds, chatting)
      val allWrites = (ra.writes ++ rb.writes).toSeq
      val sizes = allWrites.map(_._2.length).toSet
      assert(
        sizes == Set(frame.Frame.Size),
        s"chatting=$chatting: frame sizes $sizes, expected only ${frame.Frame.Size}"
      )
      assert(
        allWrites.forall(_._1.length == token.RetrievalToken.Length),
        s"chatting=$chatting: a write token was not full length"
      )
      val readLens = (ra.reads ++ rb.reads).map(_.length).toSet
      assert(readLens == Set(token.RetrievalToken.Length), s"read token lengths $readLens")
      // The notify layer has the same no-size-leak requirement (FR-012 notify path).
      val labelLens = (ra.signals ++ rb.signals).map(_._2.length).toSet
      assert(labelLens.size == 1, s"chatting=$chatting: notify label lengths $labelLens leak")

  test(
    "the CHATTING and IDLE store observables are SHAPE-identical (counts, sizes, token lengths)"
  ):
    // ARCHITECTURE.md §6: "look identical whether chatting or idle" — but note what this compares
    // and what it does not. SHAPE is counts, frame sizes and token lengths. It is NOT the frame
    // bytes: those DO distinguish the two worlds, via retransmit repetition, which the recorded-gap
    // test below pins. Naming this test for the shape it actually compares rather than for "the
    // whole FR-012 claim" is the point — an earlier draft claimed the latter and would have read as
    // evidence against a leak it never looked at.
    val (busyA, busyB, busyDelivered) = drive(Rounds, chatting = true)
    val (idleA, idleB, idleDelivered) = drive(Rounds, chatting = false)
    def shape(rec: Recorder): (Int, Int, Int, Set[Int], Set[Int]) =
      (
        rec.writes.size,
        rec.reads.size,
        rec.signals.size,
        rec.writes.map(_._2.length).toSet,
        rec.writes.map(_._1.length).toSet
      )
    assert(shape(busyA) == shape(idleA), s"initiator: ${shape(busyA)} vs ${shape(idleA)}")
    assert(shape(busyB) == shape(idleB), s"responder: ${shape(busyB)} vs ${shape(idleB)}")
    // ANTI-VACUITY: the busy world must really have carried traffic, or "identical" is trivial —
    // two idle worlds are identical for free, which is exactly the bug the shared-notify `Fabric`
    // fix uncovered in this file's first revision.
    assert(busyDelivered > 0, "the busy world delivered nothing — it is not a busy world")
    assert(idleDelivered == 0, "the idle world delivered something — it is not an idle world")
    assert(busyA.writes.size == Rounds)

  // ===================================================== no structural marker in the bytes

  test("no byte offset is constant across frames — a plaintext tag or length field would show"):
    // The limit of what a structural test can say about indistinguishability. It cannot show the
    // frames look random (that is the AEAD's job, pinned in RoundTransportSpec/T042). It CAN show no
    // offset carries a fixed value across every frame, which is what a version byte, a type tag, a
    // length prefix or an unencrypted counter would look like — and it covers real and cover frames
    // together, so a marker distinguishing the two classes is caught as well.
    val (ra, rb, _) = drive(Rounds, chatting = true)
    val (ia, ib, _) = drive(Rounds, chatting = false)
    val frames = (ra.writes ++ rb.writes ++ ia.writes ++ ib.writes).map(_._2).toSeq
    assert(frames.size >= 4 * Rounds, "not enough frames sampled to say anything")
    val constant = (0 until frame.Frame.Size).filter { off =>
      val v = frames.head(off)
      frames.forall(_(off) == v)
    }
    assert(constant.isEmpty, s"byte offsets $constant are constant across all frames")

  test("write TOKENS never recur — nothing for the store to cluster on (FR-014)"):
    val (ra, rb, delivered) = drive(Rounds, chatting = true)
    assert(delivered > 0, "the busy world must actually deliver — else this is an idle world")
    val writes = (ra.writes ++ rb.writes).toSeq
    val tokens = writes.map(w => PqTestKit.hex(w._1))
    assert(tokens.distinct.size == tokens.size, "a write token recurred (FR-014)")
    val reads = (ra.reads ++ rb.reads).map(PqTestKit.hex).toSeq
    assert(reads.distinct.size == reads.size, "a read token recurred (FR-014)")

  test("RECORDED GAP: frame BYTES repeat under ARQ retransmit, and idle cover frames never do"):
    // THIS TEST PINS A LEAK, NOT A GUARANTEE. It asserts what the code does today so that a fix is
    // noticed; it is not a statement that the current behaviour is correct.
    //
    // Measured (Rounds=40, both sides sending every round vs. both idle):
    //   busy: 80 writes, 22 DISTINCT frames   — stop-and-wait re-presents the CACHED head wire
    //   idle: 80 writes, 80 DISTINCT frames   — every cover frame is freshly random
    //
    // The repetition is deliberate at the ratchet layer: `Engine` re-encrypts a head only when it is
    // new or our ack advanced, "so the ratchet does not advance per retransmit". The retransmit goes
    // out under a FRESH round token each time (tokens are non-recurrent, asserted above), so nothing
    // is linkable by address — but the 256 bytes themselves are byte-identical.
    //
    // A passive store therefore has a distinguisher that the per-round budget and the size uniformity
    // do not cover: COUNT REPEATED BLOBS. Duplicates ⇒ someone is retransmitting real content;
    // no duplicates ⇒ idle. That is precisely the active-vs-idle inference FR-012 exists to prevent,
    // and it is invisible to every count/size assertion above — including `RoundTransportSpec`'s
    // "active and idle STORE-WRITE traces are indistinguishable", which compares only counts, sizes
    // and token lengths.
    //
    // Recorded as an open §9 Q3 residual in design/continuous-pq-ratchet.md and ARCHITECTURE.md §6.
    // No label is affected: `DEV, NO METADATA PRIVACY` already stands and Phase C is not reached, so
    // no shipped promise is broken — but the claim "a real frame and a carrier frame are
    // byte-indistinguishable" is not true of a RETRANSMITTED real frame across rounds.
    val (ra, rb, delivered) = drive(Rounds, chatting = true)
    val (ia, ib, idleDelivered) = drive(Rounds, chatting = false)
    assert(delivered > 0, "the busy world must actually deliver")
    assert(idleDelivered == 0, "the idle world must deliver nothing")
    val busy = (ra.writes ++ rb.writes).map(w => PqTestKit.hex(w._2)).toSeq
    val idle = (ia.writes ++ ib.writes).map(w => PqTestKit.hex(w._2)).toSeq
    assert(
      idle.distinct.size == idle.size,
      s"cover frames repeated: ${idle.distinct.size}/${idle.size}"
    )
    assert(
      busy.distinct.size < busy.size,
      "busy frames no longer repeat — if the retransmit path was changed to re-encrypt, DELETE this " +
        "test and the Q3 residual it records, and tighten the claim in ARCHITECTURE.md \u00a76"
    )

  // ===================================================== the invariant survives a rekey

  test("the budget and the 256-byte shape hold ACROSS a continuous-PQ rekey"):
    // The rekey streams ~19 KEM chunk frames over the same lane. §5's whole compatibility argument
    // is that they ride inside the MK-sealed inner block and so cannot change the observable. Stated
    // here as the same per-round budget, on both platforms, over the window a rekey actually runs
    // in. (`PqRekeyCrossSpec` measures this too; it is repeated here because THIS file is the one
    // that names the unlinkability assumption, and a reader checking that assumption should not have
    // to know the rekey suite exists.)
    val (alice, bob, ra, rb, pid) = world()
    for i <- 0 until PqRekey.IdleMinSteps do
      alice.sendMessage(pid, s"a$i"): Unit
      bob.sendMessage(pid, s"b$i"): Unit
      for r <- 1 + i * 12 until 13 + i * 12 do
        alice.tick(r.toLong): Unit; bob.tick(r.toLong): Unit
        alice.drainEvents(): Unit; bob.drainEvents(): Unit
    val beforeRekey = ra.writes.size
    for r <- 200 until 700 do
      alice.tick(r.toLong): Unit; bob.tick(r.toLong): Unit
      alice.drainEvents(): Unit; bob.drainEvents(): Unit
    assert(alice.rekeyStatus(pid).get.epochsFolded >= 1, "a rekey must actually have run")
    // One write per round through the rekey window too — no burst.
    assert(
      ra.writes.size == beforeRekey + 500,
      s"rekey changed the write budget: ${ra.writes.size}"
    )
    assert(
      (ra.writes ++ rb.writes).forall(_._2.length == frame.Frame.Size),
      "a rekey frame was not 256 bytes"
    )
