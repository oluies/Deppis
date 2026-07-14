package engine

import kem.HybridKem
import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** Post-quantum pairing prekey (US7, Option A): the add-buddy handshake optionally runs a hybrid-KEM
  * (X25519+ML-KEM-768) prekey exchange whose shared secret is folded into the INITIAL content root
  * via `KeySchedule.pqContentRoot`, WITHOUT touching the DH ratchet. This JVM suite proves:
  *   - the initiator (decaps) and responder (encaps) derive a BYTE-IDENTICAL PQ content root, so the
  *     two seeded ratchets interoperate — driven end to end through the engine, one side `sendMessage`s
  *     and the other receives it;
  *   - the PQ root DIFFERS from the classical (pre-KEM) root — the KEM secret actually changed it;
  *   - the state machine fails closed (a matched PQ pairing without the ciphertext is refused) and
  *     clears its parked KEM secret on mismatch / removeBuddy;
  *   - the classical (legacy / no-KEM) path is unchanged and still delivers.
  *
  * HONEST LABELING (Constitution IV): this hardens only the pairing SEED; the ongoing per-message
  * X25519 DH ratchet stays classical. The tests assert the seed, not any per-message PQ property. */
class PqPairingSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")
  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  /** A shared in-memory backend modelling obsd (same shape as RoundTransportSpec's): one token→frame
    * store + a notify aggregator connecting `signal`→`fetchDigest` per (round, label tag), so two
    * engines wired to it drive the full stop-and-wait ARQ flow automatically. */
  private final class FakeBackend:
    val store = mutable.Map.empty[String, Array[Byte]]
    private val bits = mutable.Map.empty[(Long, Vector[Byte]), mutable.Set[Int]]
    def transport(): RoundTransport = new RoundTransport:
      def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
        store(hex(token)) = frame; true
      def retrieve(token: Array[Byte]): Option[Array[Byte]] = store.remove(hex(token))
      override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
        bits.getOrElseUpdate((roundId, label.toVector), mutable.Set.empty) += bit
      def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
        val out = new Array[Byte](64)
        bits
          .get((roundId, clientLabel.toVector))
          .foreach(_.foreach(b => out(b >> 3) = (out(b >> 3) | (1 << (b & 7))).toByte))
        out

  private def converse(a: Engine, b: Engine, from: Long, to: Long): (Seq[String], Seq[String]) =
    val ma = mutable.ArrayBuffer.empty[String]; val mb = mutable.ArrayBuffer.empty[String]
    for r <- from to to do
      a.tick(r); b.tick(r)
      ma ++= a.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      mb ++= b.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    (ma.toSeq, mb.toSeq)

  /** Run the full PQ pairing prekey between two engines over one backend; returns (alice, bob, pid). */
  private def pqPair(be: FakeBackend): (Engine, Engine, String) =
    val aLabel = "alice".getBytes; val bLabel = "bob".getBytes
    val alice = Engine(Some(be.transport()), clientLabel = aLabel)
    val bob = Engine(Some(be.transport()), clientLabel = bLabel)
    // Initiator generates the hybrid-KEM keypair and DEFERS its ratchet.
    val aRes = alice
      .addBuddy(
        secret("oob"),
        BuddyRole.Initiator,
        peerNotifyLabel = bLabel,
        initiatePqPrekey = true
      )
      .toOption
      .get
    val kemPub = aRes.kemPublicKey.get
    assert(kemPub.length == HybridKem.PublicKeyBytes)
    assert(aRes.kemCiphertext.isEmpty)
    // Responder encapsulates to it, mixes, seeds NOW, returns the ciphertext.
    val bRes = bob
      .addBuddy(
        secret("oob"),
        BuddyRole.Responder,
        peerNotifyLabel = aLabel,
        initiatorKemPublicKey = Some(kemPub)
      )
      .toOption
      .get
    val ct = bRes.kemCiphertext.get
    assert(ct.length == HybridKem.CiphertextBytes)
    assert(bRes.kemPublicKey.isEmpty)
    assert(aRes.pairId == bRes.pairId, "the symmetric pairId/safety number is unchanged by the KEM")
    assert(aRes.safetyNumber == bRes.safetyNumber)
    // Initiator completes: the ciphertext arrives OOB alongside the safety-number comparison.
    assert(alice.confirmBuddy(aRes.pairId, matched = true, kemCiphertext = Some(ct)).isRight)
    assert(bob.confirmBuddy(bRes.pairId, matched = true).isRight)
    alice.drainEvents(); bob.drainEvents()
    (alice, bob, aRes.pairId)

  test("PQ pairing: initiator (decaps) and responder (encaps) seed INTEROPERABLE ratchets"):
    val be = FakeBackend()
    val (alice, bob, pid) = pqPair(be)
    assert(alice.confirmedCount == 1 && bob.confirmedCount == 1)
    // A message round-trips ⇒ both sides seeded a byte-identical PQ content root (else the DH double
    // ratchet's header keys, derived from that seed, would not match and nothing would decrypt).
    assert(alice.sendMessage(pid, "meet at noon") == Right(1))
    val (_, bobMsgs) = converse(alice, bob, 1, 12)
    assert(bobMsgs == Seq("meet at noon"), s"bob got $bobMsgs")
    // Bidirectional: the responder replies after receiving (initiator-sends-first).
    assert(bob.sendMessage(pid, "see you there") == Right(1))
    val (aliceMsgs, _) = converse(alice, bob, 13, 26)
    assert(aliceMsgs == Seq("see you there"), s"alice got $aliceMsgs")

  test("the KEM secret actually changes the seed: PQ content root DIFFERS from the classical one"):
    // Deterministic primitive-level check, single source of truth via KeySchedule.pqContentRoot. Both
    // the encaps side and the decaps side agree on the SAME shared secret, so they mix to the SAME
    // PQ root — and that root differs from the classical content root.
    val pairKey = handshake.Handshake.init(secret("oob")).pairKey
    val base = KeySchedule.contentRoot(pairKey)
    val (pub, sec) = HybridKem.keypair()
    val (ct, ssEnc) = HybridKem.encaps(pub)
    val ssDec = HybridKem.decaps(ct, sec)
    assert(ssEnc.sameElements(ssDec), "encaps/decaps agree (precondition for an identical seed)")
    val rootResponder = KeySchedule.pqContentRoot(base, ssEnc)
    val rootInitiator = KeySchedule.pqContentRoot(base, ssDec)
    assert(rootResponder.sameElements(rootInitiator), "both sides derive a byte-identical PQ root")
    assert(!rootResponder.sameElements(base), "the KEM secret must change the content root")

  test("FAIL CLOSED: a matched PQ pairing WITHOUT the ciphertext is refused, then retryable"):
    val alice = Engine()
    val res = alice
      .addBuddy(secret("oob"), BuddyRole.Initiator, initiatePqPrekey = true)
      .toOption
      .get
    // No ciphertext ⇒ refuse (do not silently downgrade to the classical seed); the pairing is NOT
    // confirmed and the parked KEM secret is retained for a corrected retry.
    assert(
      alice.confirmBuddy(res.pairId, matched = true) ==
        Left(EngineError("pq_prekey_required", "responder KEM ciphertext required to confirm"))
    )
    assert(alice.confirmedCount == 0, "not confirmed without the ciphertext")
    // A separate responder produces the matching ciphertext; the retry now completes.
    val bob = Engine()
    val ct = bob
      .addBuddy(
        secret("oob"),
        BuddyRole.Responder,
        initiatorKemPublicKey = Some(res.kemPublicKey.get)
      )
      .toOption
      .get
      .kemCiphertext
      .get
    assert(alice.confirmBuddy(res.pairId, matched = true, kemCiphertext = Some(ct)).isRight)
    assert(alice.confirmedCount == 1)
    // The parked state is consumed: a second completion finds no pending prekey (already confirmed).
    assert(alice.confirmBuddy(res.pairId, matched = true, kemCiphertext = Some(ct)).isLeft)

  test("FAIL CLOSED on a corrupt ciphertext: the parked prekey is retained and a retry completes"):
    // A corrupt (wrong-length) ciphertext makes decaps throw. The completion must be refused WITHOUT
    // dropping the parked prekey — otherwise a later confirm would silently establish an un-seeded /
    // non-PQ buddy (the fail-open regression the review caught). The corrected retry must complete.
    val be = FakeBackend()
    val aLabel = "alice".getBytes; val bLabel = "bob".getBytes
    val alice = Engine(Some(be.transport()), clientLabel = aLabel)
    val bob = Engine(Some(be.transport()), clientLabel = bLabel)
    val aRes = alice
      .addBuddy(
        secret("oob"),
        BuddyRole.Initiator,
        peerNotifyLabel = bLabel,
        initiatePqPrekey = true
      )
      .toOption
      .get
    val goodCt = bob
      .addBuddy(
        secret("oob"),
        BuddyRole.Responder,
        peerNotifyLabel = aLabel,
        initiatorKemPublicKey = aRes.kemPublicKey
      )
      .toOption
      .get
      .kemCiphertext
      .get
    // Corrupt (wrong-length) ciphertext ⇒ decaps throws ⇒ refused, NOT confirmed.
    assert(
      alice.confirmBuddy(aRes.pairId, matched = true, kemCiphertext = Some(new Array[Byte](10))) ==
        Left(EngineError("pq_prekey_failed", "prekey completion failed"))
    )
    assert(alice.confirmedCount == 0, "a corrupt ciphertext must not confirm the buddy")
    // The parked prekey is RETAINED (still fail closed): a no-ciphertext confirm is still refused, not
    // silently downgraded to a classical confirm.
    assert(
      alice.confirmBuddy(aRes.pairId, matched = true) ==
        Left(EngineError("pq_prekey_required", "responder KEM ciphertext required to confirm"))
    )
    // The corrected retry with the good ciphertext now completes and the buddy actually delivers.
    assert(alice.confirmBuddy(aRes.pairId, matched = true, kemCiphertext = Some(goodCt)).isRight)
    assert(bob.confirmBuddy(aRes.pairId, matched = true).isRight)
    alice.drainEvents(); bob.drainEvents()
    alice.sendMessage(aRes.pairId, "after retry")
    val (_, bobMsgs) = converse(alice, bob, 1, 12)
    assert(bobMsgs == Seq("after retry"), s"bob got $bobMsgs")

  test("mismatch on a PQ initiator establishes nothing and clears the parked KEM secret"):
    val alice = Engine()
    val res = alice
      .addBuddy(secret("oob"), BuddyRole.Initiator, initiatePqPrekey = true)
      .toOption
      .get
    assert(alice.confirmBuddy(res.pairId, matched = false).isRight)
    assert(alice.confirmedCount == 0)
    assert(alice.drainEvents().isEmpty)
    // Parked state cleared: a later "complete" cannot find a pending prekey (nothing to re-seed).
    assert(
      alice
        .confirmBuddy(res.pairId, matched = true, kemCiphertext = Some(new Array[Byte](0)))
        .isLeft
    )

  test("removeBuddy on a still-pending PQ initiator succeeds and clears the parked KEM secret"):
    val alice = Engine()
    val res = alice
      .addBuddy(secret("oob"), BuddyRole.Initiator, initiatePqPrekey = true)
      .toOption
      .get
    assert(alice.buddyCount == 1)
    assert(alice.removeBuddy(res.pairId).isRight)
    assert(alice.buddyCount == 0)
    // The prekey is gone: confirming the removed pair finds no pending state and cannot re-seed.
    assert(
      alice
        .confirmBuddy(res.pairId, matched = true, kemCiphertext = Some(new Array[Byte](0)))
        .isLeft
    )

  test("a malformed KEM public key is rejected without adding the buddy (responder path)"):
    val bob = Engine()
    val bad = new Array[Byte](HybridKem.PublicKeyBytes) // all-zero ⇒ low-order X25519, rejected
    val r = bob.addBuddy(secret("oob"), BuddyRole.Responder, initiatorKemPublicKey = Some(bad))
    assert(r == Left(EngineError("pq_prekey_failed", "invalid KEM public key")))
    assert(bob.buddyCount == 0, "a bad peer key must add nothing")

  test("CLASSICAL (legacy) path is unchanged: no KEM material ⇒ non-PQ seed, still delivers"):
    val be = FakeBackend()
    val alice = Engine(Some(be.transport()), clientLabel = "alice".getBytes)
    val bob = Engine(Some(be.transport()), clientLabel = "bob".getBytes)
    val pid = alice
      .addBuddy(secret("oob"), BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes)
      .toOption
      .get
      .pairId
    // No KEM fields on either result.
    val aRes = alice.addBuddy(secret("oob2"), BuddyRole.Initiator).toOption.get
    assert(aRes.kemPublicKey.isEmpty && aRes.kemCiphertext.isEmpty)
    bob.addBuddy(secret("oob"), BuddyRole.Responder, peerNotifyLabel = "alice".getBytes)
    alice.confirmBuddy(pid, matched = true); bob.confirmBuddy(pid, matched = true)
    alice.drainEvents(); bob.drainEvents()
    alice.sendMessage(pid, "classical hi")
    val (_, bobMsgs) = converse(alice, bob, 1, 12)
    assert(bobMsgs == Seq("classical hi"))

  // ---- JSON boundary (the versioned wire contract) with the new base64 PQ fields ----

  test("handle(addBuddy/confirmBuddy) round-trips the base64 PQ fields and pairs over the wire"):
    val ca = EngineCodec(Engine())
    val cb = EngineCodec(Engine())
    val add = ujson.read(
      ca.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"initiator","pqPrekey":true}}"""
      )
    )
    val pairId = add("result")("pairId").str
    val kemPub = add("result")("kemPublicKey").str // base64, present on the PQ initiator result
    assert(kemPub.nonEmpty && !add("result").obj.contains("kemCiphertext"))
    val respAdd = ujson.read(
      cb.handle(
        s"""{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"responder","initiatorKemPublicKey":"$kemPub"}}"""
      )
    )
    val ct = respAdd("result")("kemCiphertext").str // base64, present on the PQ responder result
    assert(ct.nonEmpty && !respAdd("result").obj.contains("kemPublicKey"))
    // Initiator completes over the wire with the ciphertext; buddyConfirmed is emitted.
    val conf = ujson.read(
      ca.handle(
        s"""{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"$pairId","matched":true,"kemCiphertext":"$ct"}}"""
      )
    )
    assert(conf("events").arr.head("event").str == "buddyConfirmed")
    // Fail closed over the wire too: a fresh PQ initiator matched WITHOUT the ciphertext is refused.
    val cc = EngineCodec(Engine())
    val add2 = ujson.read(
      cc.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"x","role":"initiator","pqPrekey":true}}"""
      )
    )
    val err = ujson.read(
      cc.handle(
        s"""{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"${add2("result")(
            "pairId"
          ).str}","matched":true}}"""
      )
    )
    assert(err("error")("code").str == "pq_prekey_required")

  test("handle(addBuddy) with malformed base64 KEM material maps to bad_request (no throw)"):
    val resp = EngineCodec(Engine()).handle(
      """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"responder","initiatorKemPublicKey":"!!!not-base64!!!"}}"""
    )
    assert(ujson.read(resp)("error")("code").str == "bad_request")
