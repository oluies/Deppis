package engine

import engine.PqTestKit.{FakeBackend, converse}
import kem.HybridKem
import org.scalatest.funsuite.AnyFunSuite

/** Runs under Node (Scala.js): proves the GENERATED JS engine path performs the full post-quantum
  * pairing prekey (US7) — the initiator generates a hybrid-KEM keypair (X25519 via @noble/curves +
  * ML-KEM-768 via @noble/post-quantum), the responder encapsulates + returns a key-confirmation tag,
  * the initiator decapsulates, verifies the tag, and both seed a byte-identical PQ content root so a
  * message actually round-trips through the JS ratchet. The JS `kem.HybridKem` interoperates with the
  * JVM one (KAT-pinned in HybridKemSpec/HybridKemJsSpec); the CROSS-PLATFORM VECTOR test below replays
  * the JVM-pinned `pqContentRoot`/`pqConfirmTag` values, so a JVM initiator and a JS responder provably
  * reach the same seed + tag through the engine mixing layer.
  *
  * HONEST LABELING (Constitution IV): this hardens only the pairing SEED; the ongoing per-message
  * X25519 DH ratchet stays classical. */
class PqPairingJsSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")

  test("JS PQ pairing: initiator+responder run the KEM exchange (with tag) and exchange a message"):
    val be = FakeBackend()
    val aLabel = "alice".getBytes; val bLabel = "bob".getBytes
    val alice = new Engine(Some(be.transport()), clientLabel = aLabel)
    val bob = new Engine(Some(be.transport()), clientLabel = bLabel)
    val aRes = alice
      .addBuddy(
        secret("oob"),
        BuddyRole.Initiator,
        peerNotifyLabel = bLabel,
        initiatePqPrekey = true
      )
      .toOption
      .get
    assert(aRes.kemPublicKey.get.length == HybridKem.PublicKeyBytes)
    val bRes = bob
      .addBuddy(
        secret("oob"),
        BuddyRole.Responder,
        peerNotifyLabel = aLabel,
        initiatorKemPublicKey = aRes.kemPublicKey
      )
      .toOption
      .get
    assert(bRes.kemCiphertext.get.length == HybridKem.CiphertextBytes)
    assert(bRes.kemConfirmTag.isDefined, "responder returns a key-confirmation tag")
    assert(aRes.pairId == bRes.pairId, "pairId unchanged by the KEM (symmetric OOB derivation)")
    assert(
      alice
        .confirmBuddy(
          aRes.pairId,
          matched = true,
          kemCiphertext = bRes.kemCiphertext,
          kemConfirmTag = bRes.kemConfirmTag
        )
        .isRight
    )
    assert(bob.confirmBuddy(bRes.pairId, matched = true).isRight)
    alice.drainEvents(); bob.drainEvents()
    // A delivered message proves both JS ratchets seeded a byte-identical PQ content root.
    assert(alice.sendMessage(aRes.pairId, "js pq hello") == Right(1))
    val (_, bobMsgs) = converse(alice, bob, 1, 12)
    assert(bobMsgs == Seq("js pq hello"), s"bob got $bobMsgs")

  test(
    "JS KEY CONFIRMATION: a SAME-LENGTH ciphertext bit-flip fails closed with pq_confirm_failed"
  ):
    val alice = new Engine()
    val bob = new Engine()
    val aRes =
      alice.addBuddy(secret("oob"), BuddyRole.Initiator, initiatePqPrekey = true).toOption.get
    val bRes = bob
      .addBuddy(secret("oob"), BuddyRole.Responder, initiatorKemPublicKey = aRes.kemPublicKey)
      .toOption
      .get
    val flipped = bRes.kemCiphertext.get.clone(); flipped(0) = (flipped(0) ^ 0x01).toByte
    assert(
      alice.confirmBuddy(
        aRes.pairId,
        matched = true,
        kemCiphertext = Some(flipped),
        kemConfirmTag = bRes.kemConfirmTag
      ) == Left(EngineError("pq_confirm_failed", "KEM key confirmation failed"))
    )
    assert(alice.confirmedCount == 0)
    // Parked prekey retained ⇒ the untampered completion still works.
    assert(
      alice
        .confirmBuddy(
          aRes.pairId,
          matched = true,
          kemCiphertext = bRes.kemCiphertext,
          kemConfirmTag = bRes.kemConfirmTag
        )
        .isRight
    )

  test("JS PQ seed check: encaps/decaps agree and change the content root"):
    val base = KeySchedule.contentRoot(handshake.Handshake.init(secret("oob")).pairKey)
    val (pub, sec) = HybridKem.keypair()
    val (ct, ssEnc) = HybridKem.encaps(pub)
    val ssDec = HybridKem.decaps(ct, sec)
    assert(ssEnc.sameElements(ssDec))
    assert(
      KeySchedule.pqContentRoot(base, ssEnc).sameElements(KeySchedule.pqContentRoot(base, ssDec))
    )
    assert(!KeySchedule.pqContentRoot(base, ssEnc).sameElements(base))

  test("JS CROSS-PLATFORM VECTOR: pqContentRoot + pqConfirmTag match the JVM-pinned values"):
    // Same fixed (base, kemSharedSecret) constants as PqPairingSpec; the pinned hex was generated on
    // the JVM. Matching here proves the engine mixing layer (HMAC-SHA256) is byte-identical JVM↔JS.
    val base = PqTestKit.unhex("11" * 32)
    val ss = PqTestKit.unhex("22" * 32)
    val rootP = KeySchedule.pqContentRoot(base, ss)
    val tag = KeySchedule.pqConfirmTag(rootP)
    assert(
      PqTestKit.hex(rootP) == "8b44543f08bd807c091521b8de5061ea51da69c3647d0d72c45cf0fdeb2864df"
    )
    assert(PqTestKit.hex(tag) == "35c5417e1ec686221c670d04f7dfc67e8167184dc504f6b901291bd905f5ff31")

  test("JS fail-closed: a matched PQ pairing without the ciphertext + tag is refused"):
    val alice = new Engine()
    val res =
      alice.addBuddy(secret("oob"), BuddyRole.Initiator, initiatePqPrekey = true).toOption.get
    assert(
      alice
        .confirmBuddy(res.pairId, matched = true)
        .left
        .toOption
        .map(_.code)
        .contains("pq_prekey_required")
    )
    assert(alice.confirmedCount == 0)

  test("JS inconsistent PQ arg combos are rejected with invalid_arg"):
    val e = new Engine()
    assert(
      e.addBuddy(
        secret("oob"),
        BuddyRole.Initiator,
        initiatorKemPublicKey = Some(new Array[Byte](1))
      ).left
        .toOption
        .map(_.code)
        .contains("invalid_arg")
    )
    assert(
      e.addBuddy(secret("oob"), BuddyRole.Responder, initiatePqPrekey = true)
        .left
        .toOption
        .map(_.code)
        .contains("invalid_arg")
    )

  test("JS JSON boundary carries the base64 PQ fields (incl. confirm tag) end to end"):
    val ca = new EngineCodec(new Engine())
    val cb = new EngineCodec(new Engine())
    val add = ujson.read(
      ca.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"initiator","pqPrekey":true}}"""
      )
    )
    val pairId = add("result")("pairId").str
    val kemPub = add("result")("kemPublicKey").str
    val respAdd = ujson.read(
      cb.handle(
        s"""{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"responder","initiatorKemPublicKey":"$kemPub"}}"""
      )
    )
    val ct = respAdd("result")("kemCiphertext").str
    val tag = respAdd("result")("kemConfirmTag").str
    val conf = ujson.read(
      ca.handle(
        s"""{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"$pairId","matched":true,"kemCiphertext":"$ct","kemConfirmTag":"$tag"}}"""
      )
    )
    assert(conf("events").arr.head("event").str == "buddyConfirmed")
