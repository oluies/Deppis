package engine

import engine.PqTestKit.{FakeBackend, converse}
import kem.HybridKem
import org.scalatest.funsuite.AnyFunSuite

/** Post-quantum pairing prekey (US7, Option A): the add-buddy handshake optionally runs a hybrid-KEM
  * (X25519+ML-KEM-768) prekey exchange whose shared secret is folded into the INITIAL content root
  * via `KeySchedule.pqContentRoot`, WITHOUT touching the DH ratchet. This JVM suite proves:
  *   - the initiator (decaps) and responder (encaps) derive a BYTE-IDENTICAL PQ content root, so the
  *     two seeded ratchets interoperate — driven end to end through the engine, one side `sendMessage`s
  *     and the other receives it;
  *   - the PQ root DIFFERS from the classical (pre-KEM) root — the KEM secret actually changed it;
  *   - a KEY-CONFIRMATION TAG makes SAME-LENGTH KEM tampering fail closed (ML-KEM's implicit rejection
  *     otherwise "succeeds" silently) — a bit-flipped ciphertext, a substituted public key, or a
  *     tampered tag are all rejected with `pq_confirm_failed`;
  *   - the state machine fails closed (missing ciphertext/tag) and clears its parked KEM secret on
  *     mismatch / removeBuddy; and the classical (legacy / no-KEM) path is unchanged and still delivers.
  *
  * HONEST LABELING (Constitution IV): this hardens only the pairing SEED; the ongoing per-message
  * X25519 DH ratchet stays classical. The tests assert the seed, not any per-message PQ property. */
class PqPairingSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")

  /** Raw PQ prekey material exchanged out of band, plus the two engines and the pairId. */
  private final case class PqSetup(
      alice: Engine,
      bob: Engine,
      pid: String,
      kemPublicKey: Array[Byte],
      kemCiphertext: Array[Byte],
      kemConfirmTag: Array[Byte]
  )

  /** Run initiator `addBuddy` + responder `addBuddy` over one backend, returning the raw KEM material
    * (WITHOUT the initiator's completing `confirmBuddy`, so tamper tests can drive it). */
  private def pqSetup(be: FakeBackend): PqSetup =
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
    val kemPub = aRes.kemPublicKey.get
    assert(kemPub.length == HybridKem.PublicKeyBytes)
    assert(aRes.kemCiphertext.isEmpty && aRes.kemConfirmTag.isEmpty)
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
    val tag = bRes.kemConfirmTag.get
    assert(ct.length == HybridKem.CiphertextBytes)
    assert(bRes.kemPublicKey.isEmpty)
    assert(aRes.pairId == bRes.pairId, "the symmetric pairId/safety number is unchanged by the KEM")
    assert(aRes.safetyNumber == bRes.safetyNumber)
    PqSetup(alice, bob, aRes.pairId, kemPub, ct, tag)

  /** Full PQ pairing: setup + initiator completes with the good ciphertext + tag + both confirm. */
  private def pqPair(be: FakeBackend): (Engine, Engine, String) =
    val s = pqSetup(be)
    assert(
      s.alice
        .confirmBuddy(
          s.pid,
          matched = true,
          kemCiphertext = Some(s.kemCiphertext),
          kemConfirmTag = Some(s.kemConfirmTag)
        )
        .isRight
    )
    assert(s.bob.confirmBuddy(s.pid, matched = true).isRight)
    s.alice.drainEvents(); s.bob.drainEvents()
    (s.alice, s.bob, s.pid)

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

  test("KEY CONFIRMATION: a SAME-LENGTH ciphertext bit-flip fails closed with pq_confirm_failed"):
    // ML-KEM implicit rejection: a same-length tampered ciphertext does NOT make decaps throw — it
    // yields a different shared secret ⇒ a different rootP ⇒ a different tag ⇒ the CT tag compare fails.
    val s = pqSetup(FakeBackend())
    val flipped = s.kemCiphertext.clone(); flipped(0) = (flipped(0) ^ 0x01).toByte
    assert(flipped.length == s.kemCiphertext.length, "same length (not a length check)")
    assert(
      s.alice.confirmBuddy(
        s.pid,
        matched = true,
        kemCiphertext = Some(flipped),
        kemConfirmTag = Some(s.kemConfirmTag)
      ) == Left(EngineError("pq_confirm_failed", "KEM key confirmation failed"))
    )
    assert(s.alice.confirmedCount == 0, "a tampered ciphertext must not confirm the buddy")
    // The parked prekey is RETAINED: the legitimate (untampered) completion still works.
    assert(
      s.alice
        .confirmBuddy(
          s.pid,
          matched = true,
          kemCiphertext = Some(s.kemCiphertext),
          kemConfirmTag = Some(s.kemConfirmTag)
        )
        .isRight
    )
    assert(s.alice.confirmedCount == 1)

  test("KEY CONFIRMATION: a substituted responder public key fails closed"):
    // An attacker who substitutes a DIFFERENT initiator public key to the responder gets a ciphertext
    // whose shared secret the real initiator cannot reproduce ⇒ tag mismatch. We simulate by pairing a
    // second responder to a DIFFERENT initiator key and feeding its (ct, tag) to the first initiator.
    val s = pqSetup(FakeBackend())
    val attacker = Engine()
    val evilInit = attacker
      .addBuddy(secret("oob"), BuddyRole.Initiator, initiatePqPrekey = true)
      .toOption
      .get
      .kemPublicKey
      .get
    val evilBob = Engine()
    val evilRes = evilBob
      .addBuddy(secret("oob"), BuddyRole.Responder, initiatorKemPublicKey = Some(evilInit))
      .toOption
      .get
    // Feed the wrong-key ciphertext+tag to the real initiator: decaps yields a secret it cannot match.
    assert(
      s.alice.confirmBuddy(
        s.pid,
        matched = true,
        kemCiphertext = evilRes.kemCiphertext,
        kemConfirmTag = evilRes.kemConfirmTag
      ) == Left(EngineError("pq_confirm_failed", "KEM key confirmation failed"))
    )
    assert(s.alice.confirmedCount == 0)

  test("KEY CONFIRMATION: a tampered confirmation tag (correct ciphertext) fails closed"):
    val s = pqSetup(FakeBackend())
    val badTag = s.kemConfirmTag.clone(); badTag(0) = (badTag(0) ^ 0xff).toByte
    assert(
      s.alice.confirmBuddy(
        s.pid,
        matched = true,
        kemCiphertext = Some(s.kemCiphertext),
        kemConfirmTag = Some(badTag)
      ) == Left(EngineError("pq_confirm_failed", "KEM key confirmation failed"))
    )
    assert(s.alice.confirmedCount == 0)

  test("FAIL CLOSED: a matched PQ pairing WITHOUT the ciphertext + tag is refused, then retryable"):
    val s = pqSetup(FakeBackend())
    // No ciphertext/tag ⇒ refuse (do not silently downgrade to the classical seed); NOT confirmed.
    assert(
      s.alice.confirmBuddy(s.pid, matched = true) ==
        Left(
          EngineError(
            "pq_prekey_required",
            "responder KEM ciphertext and confirmation tag required to confirm"
          )
        )
    )
    // Ciphertext without the tag is also refused (fail closed on the missing authenticator).
    assert(
      s.alice
        .confirmBuddy(s.pid, matched = true, kemCiphertext = Some(s.kemCiphertext))
        .swap
        .toOption
        .map(_.code)
        .contains("pq_prekey_required")
    )
    assert(s.alice.confirmedCount == 0, "not confirmed without the ciphertext + tag")
    // The retry with BOTH now completes.
    assert(
      s.alice
        .confirmBuddy(
          s.pid,
          matched = true,
          kemCiphertext = Some(s.kemCiphertext),
          kemConfirmTag = Some(s.kemConfirmTag)
        )
        .isRight
    )
    assert(s.alice.confirmedCount == 1)
    // The parked state is consumed: a second completion finds no pending prekey (already confirmed).
    assert(
      s.alice
        .confirmBuddy(
          s.pid,
          matched = true,
          kemCiphertext = Some(s.kemCiphertext),
          kemConfirmTag = Some(s.kemConfirmTag)
        )
        .isLeft
    )

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
        .confirmBuddy(
          res.pairId,
          matched = true,
          kemCiphertext = Some(new Array[Byte](0)),
          kemConfirmTag = Some(new Array[Byte](0))
        )
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
    assert(
      alice
        .confirmBuddy(
          res.pairId,
          matched = true,
          kemCiphertext = Some(new Array[Byte](0)),
          kemConfirmTag = Some(new Array[Byte](0))
        )
        .isLeft
    )

  test("a malformed KEM public key is rejected without adding the buddy (responder path)"):
    val bob = Engine()
    val bad = new Array[Byte](HybridKem.PublicKeyBytes) // all-zero ⇒ low-order X25519, rejected
    val r = bob.addBuddy(secret("oob"), BuddyRole.Responder, initiatorKemPublicKey = Some(bad))
    assert(r == Left(EngineError("pq_prekey_failed", "invalid KEM public key")))
    assert(bob.buddyCount == 0, "a bad peer key must add nothing")

  test("inconsistent PQ arg combinations are rejected with invalid_arg before the handshake"):
    val e = Engine()
    // (a) Initiator given a peer KEM public key (would otherwise be silently dropped → non-PQ).
    assert(
      e.addBuddy(
        secret("oob"),
        BuddyRole.Initiator,
        initiatorKemPublicKey = Some(new Array[Byte](1))
      )
        == Left(EngineError("invalid_arg", "initiator must not be given a KEM public key"))
    )
    // (b) Responder opting into PQ but supplying no initiator KEM public key to encaps to.
    assert(
      e.addBuddy(secret("oob"), BuddyRole.Responder, initiatePqPrekey = true)
        == Left(
          EngineError("invalid_arg", "responder pqPrekey requires the initiator KEM public key")
        )
    )
    assert(e.buddyCount == 0, "neither invalid combination adds a buddy")

  test("CLASSICAL (legacy) path is unchanged: no KEM material ⇒ non-PQ seed, still delivers"):
    val be = FakeBackend()
    val alice = Engine(Some(be.transport()), clientLabel = "alice".getBytes)
    val bob = Engine(Some(be.transport()), clientLabel = "bob".getBytes)
    val pid = alice
      .addBuddy(secret("oob"), BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes)
      .toOption
      .get
      .pairId
    val aRes = alice.addBuddy(secret("oob2"), BuddyRole.Initiator).toOption.get
    assert(aRes.kemPublicKey.isEmpty && aRes.kemCiphertext.isEmpty && aRes.kemConfirmTag.isEmpty)
    bob.addBuddy(secret("oob"), BuddyRole.Responder, peerNotifyLabel = "alice".getBytes)
    alice.confirmBuddy(pid, matched = true); bob.confirmBuddy(pid, matched = true)
    alice.drainEvents(); bob.drainEvents()
    alice.sendMessage(pid, "classical hi")
    val (_, bobMsgs) = converse(alice, bob, 1, 12)
    assert(bobMsgs == Seq("classical hi"))

  test("CROSS-PLATFORM VECTOR: pqContentRoot + pqConfirmTag are byte-pinned (replayed on JS)"):
    // A fixed (base, kemSharedSecret) → rootP → confirmTag vector. The SAME constants are asserted in
    // PqPairingJsSpec, so — combined with the KAT-pinned cross-platform KEM (HybridKemSpec) — a JVM
    // initiator and a JS responder provably reach the same seed + tag through the engine mixing layer.
    val base = PqTestKit.unhex("11" * 32)
    val ss = PqTestKit.unhex("22" * 32)
    val rootP = KeySchedule.pqContentRoot(base, ss)
    val tag = KeySchedule.pqConfirmTag(rootP)
    assert(
      PqTestKit.hex(rootP) == "8b44543f08bd807c091521b8de5061ea51da69c3647d0d72c45cf0fdeb2864df",
      s"rootP drifted: ${PqTestKit.hex(rootP)}"
    )
    assert(
      PqTestKit.hex(tag) == "35c5417e1ec686221c670d04f7dfc67e8167184dc504f6b901291bd905f5ff31",
      s"confirmTag drifted: ${PqTestKit.hex(tag)}"
    )

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
    val tag = respAdd("result")("kemConfirmTag").str // base64 confirmation tag
    assert(ct.nonEmpty && tag.nonEmpty && !respAdd("result").obj.contains("kemPublicKey"))
    // Initiator completes over the wire with the ciphertext + tag; buddyConfirmed is emitted.
    val conf = ujson.read(
      ca.handle(
        s"""{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"$pairId","matched":true,"kemCiphertext":"$ct","kemConfirmTag":"$tag"}}"""
      )
    )
    assert(conf("events").arr.head("event").str == "buddyConfirmed")
    // Fail closed over the wire too: a fresh PQ initiator matched WITHOUT ciphertext/tag is refused.
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

  test("handle(addBuddy) rejects inconsistent PQ arg combos with invalid_arg over the wire"):
    val codec = EngineCodec(Engine())
    val initWithKey = ujson.read(
      codec.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"initiator","initiatorKemPublicKey":"AAAA"}}"""
      )
    )
    assert(initWithKey("error")("code").str == "invalid_arg")
    val respNoKey = ujson.read(
      codec.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"responder","pqPrekey":true}}"""
      )
    )
    assert(respNoKey("error")("code").str == "invalid_arg")

  test("handle(addBuddy) with malformed base64 KEM material maps to bad_request (no throw)"):
    val resp = EngineCodec(Engine()).handle(
      """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"responder","initiatorKemPublicKey":"!!!not-base64!!!"}}"""
    )
    assert(ujson.read(resp)("error")("code").str == "bad_request")
