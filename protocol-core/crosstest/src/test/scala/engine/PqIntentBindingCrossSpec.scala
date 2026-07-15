package engine

import engine.PqTestKit.{FakeBackend, converse}
import kem.HybridKem
import org.scalatest.funsuite.AnyFunSuite

/** SINGLE-SOURCED cross-platform test (compiled into BOTH the JVM `protocolCore` and the Scala.js
  * `protocolCoreJS` builds — see build.sbt) for the PQ-INTENT BINDING that closes the STRIP-DOWNGRADE
  * gap (US7): an attacker who REMOVES the initiator's `kemPublicKey` from the out-of-band delivery used
  * to make a responder silently fall back to a classical (non-PQ) pairing. `addBuddy(pqRequired = ...)`
  * carries the authenticated OOB PQ intent — BOTH sides set it — and:
  *   - a RESPONDER with `pqRequired = true` but NO `initiatorKemPublicKey` FAILS CLOSED
  *     (`pq_prekey_required`) instead of seeding a classical pairing (the strip defense);
  *   - the intent is FOLDED into the safety-number / `pairId` derivation, so a MITM who flips the bit on
  *     one side makes the two sides derive DIFFERENT safety numbers ⇒ the OOB comparison fails;
  *   - a full `pqRequired = true` pairing on BOTH sides still completes end to end (bidirectional key
  *     confirmation intact) and a message round-trips over a byte-identical PQ seed.
  *
  * HONEST LABELING (Constitution IV): this hardens only the pairing SEED + binds the PQ intent to the
  * authenticated channel; the ongoing per-message X25519 DH ratchet stays classical. */
class PqIntentBindingCrossSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")

  test("STRIP DEFENSE: a pqRequired responder with a STRIPPED KEM public key fails closed"):
    // The exact attack: the initiator opted into PQ and sent its `kemPublicKey`, but a MITM removed it
    // from the OOB delivery. The responder ALSO expected PQ (`pqRequired = true`, from the same
    // authenticated intent), so seeing no `initiatorKemPublicKey` it refuses rather than demoting to a
    // classical pairing.
    val bob = Engine()
    assert(
      bob.addBuddy(secret("oob"), BuddyRole.Responder, pqRequired = true) ==
        Left(
          EngineError("pq_prekey_required", "PQ intent set but no initiator KEM public key arrived")
        )
    )
    assert(bob.buddyCount == 0, "a stripped-key pqRequired responder must add nothing")

  test(
    "STRIP DEFENSE: pqRequired wins the error code even if pqPrekey is (mis)set on the responder"
  ):
    // Error-code precedence: the `pqRequired` strip check runs BEFORE the `pqPrekey` arg-consistency
    // check, so a stripped key with `pqRequired = true` surfaces as `pq_prekey_required` (the "peer's PQ
    // key was stripped" UX) rather than the generic `invalid_arg` — even when a caller also (mis)set the
    // initiator-only `pqPrekey` flag on the responder. Both fail closed; this pins the code an app matches.
    val bob = Engine()
    assert(
      bob.addBuddy(
        secret("oob"),
        BuddyRole.Responder,
        initiatePqPrekey = true,
        pqRequired = true
      ) == Left(
        EngineError("pq_prekey_required", "PQ intent set but no initiator KEM public key arrived")
      )
    )
    assert(bob.buddyCount == 0)

  test("STRIP DEFENSE: WITHOUT pqRequired the same stripped delivery still demotes (control)"):
    // Control that isolates the fix: with `pqRequired = false` (the pre-change default) a responder that
    // receives no KEM material is indistinguishable from a genuinely-classical pairing, so it still adds
    // a classical buddy. `pqRequired` is precisely what makes the absence detectable + terminal.
    val bob = Engine()
    assert(bob.addBuddy(secret("oob"), BuddyRole.Responder).isRight)
    assert(bob.buddyCount == 1)

  test(
    "PQ-INTENT BINDING: an intent-flip on ONE side yields a DIFFERENT safety number (MITM caught)"
  ):
    // A MITM strips the key AND flips the responder's intent to classical to dodge the fail-closed. The
    // intent is bound into the derivation, so the two sides now derive DIFFERENT pairId/safety numbers —
    // the out-of-band safety-number comparison fails and the users never confirm.
    val alice = Engine()
    val bob = Engine()
    val aRes = alice.addBuddy(secret("oob"), BuddyRole.Initiator, pqRequired = true).toOption.get
    assert(aRes.kemPublicKey.isDefined, "pqRequired implies the initiator prekey path")
    // The responder (intent flipped to classical by the attacker) still receives the KEM key, so it does
    // NOT fail closed — but it derives under `pqRequired = false`, so its safety number diverges.
    val bRes = bob
      .addBuddy(secret("oob"), BuddyRole.Responder, initiatorKemPublicKey = aRes.kemPublicKey)
      .toOption
      .get
    assert(aRes.pairId != bRes.pairId, "flipped intent ⇒ different pairId")
    assert(aRes.safetyNumber != bRes.safetyNumber, "flipped intent ⇒ different safety number")

  test(
    "PQ-INTENT BINDING (mirror): attacker downgrades the INITIATOR — responder still fails closed"
  ):
    // The mirror of the responder-flip test: the attacker controls the INITIATOR direction. An initiator
    // driven classically (`pqRequired = false`) produces NO kemPublicKey; the responder expected PQ
    // (`pqRequired = true`), so on the stripped/absent key it fails closed — the downgrade cannot land.
    val alice = Engine()
    val aRes =
      alice.addBuddy(secret("oob"), BuddyRole.Initiator).toOption.get // classical: no KEM key
    assert(aRes.kemPublicKey.isEmpty, "a classical initiator emits no KEM public key")
    val bob = Engine()
    assert(
      bob.addBuddy(secret("oob"), BuddyRole.Responder, pqRequired = true) == Left(
        EngineError("pq_prekey_required", "PQ intent set but no initiator KEM public key arrived")
      )
    )
    assert(bob.buddyCount == 0)
    // If the attacker instead FORWARDS a FORGED KEM key (so the responder does not fail closed), the
    // responder derives under pqRequired=true while the honest classical initiator derived under false —
    // the safety numbers diverge, so the out-of-band comparison catches the downgrade.
    val forgedKey = Engine()
      .addBuddy(secret("oob"), BuddyRole.Initiator, pqRequired = true)
      .toOption
      .get
      .kemPublicKey
      .get
    val bForged = Engine()
    val bRes = bForged
      .addBuddy(
        secret("oob"),
        BuddyRole.Responder,
        initiatorKemPublicKey = Some(forgedKey),
        pqRequired = true
      )
      .toOption
      .get
    assert(
      aRes.pairId != bRes.pairId,
      "downgraded initiator vs pqRequired responder ⇒ different pairId"
    )
    assert(
      aRes.safetyNumber != bRes.safetyNumber,
      "downgraded initiator vs pqRequired responder ⇒ different safety number (OOB comparison catches it)"
    )

  test("FULL PQ pairing with pqRequired=true on BOTH sides completes and a message round-trips"):
    // The honest case: both sides agree on the PQ intent, so they derive the SAME safety number AND run
    // the full bidirectional KEM confirmation. End to end through the engine + transport.
    val be = FakeBackend()
    val aLabel = "alice".getBytes; val bLabel = "bob".getBytes
    val alice = Engine(Some(be.transport()), clientLabel = aLabel)
    val bob = Engine(Some(be.transport()), clientLabel = bLabel)
    val aRes = alice
      .addBuddy(secret("oob"), BuddyRole.Initiator, peerNotifyLabel = bLabel, pqRequired = true)
      .toOption
      .get
    val kemPub = aRes.kemPublicKey.get
    assert(kemPub.length == HybridKem.PublicKeyBytes)
    val bRes = bob
      .addBuddy(
        secret("oob"),
        BuddyRole.Responder,
        peerNotifyLabel = aLabel,
        initiatorKemPublicKey = Some(kemPub),
        pqRequired = true
      )
      .toOption
      .get
    assert(bRes.kemCiphertext.get.length == HybridKem.CiphertextBytes)
    assert(bRes.kemConfirmTag.isDefined)
    assert(aRes.pairId == bRes.pairId, "agreeing on pqRequired ⇒ identical pairId")
    assert(
      aRes.safetyNumber == bRes.safetyNumber,
      "agreeing on pqRequired ⇒ identical safety number"
    )
    // Initiator completes (key-confirms the responder's /r tag), returns its /i tag.
    val aConf = alice.confirmBuddy(
      aRes.pairId,
      matched = true,
      kemCiphertext = bRes.kemCiphertext,
      kemConfirmTag = bRes.kemConfirmTag
    )
    val initTag = aConf.toOption.get.initiatorConfirmTag
    assert(initTag.isDefined, "bidirectional confirmation intact: initiator returns its /i tag")
    // Responder verifies the /i tag and confirms (also fails closed on tampering — unchanged by this PR).
    assert(bob.confirmBuddy(bRes.pairId, matched = true, initiatorConfirmTag = initTag).isRight)
    assert(alice.confirmedCount == 1 && bob.confirmedCount == 1)
    alice.drainEvents(); bob.drainEvents()
    // A delivered message proves both sides seeded a byte-identical PQ content root.
    assert(alice.sendMessage(aRes.pairId, "pq required hi") == Right(1))
    val (_, bobMsgs) = converse(alice, bob, 1, 12)
    assert(bobMsgs == Seq("pq required hi"), s"bob got $bobMsgs")

  test("STRIP DEFENSE over the JSON boundary: a pqRequired responder without a KEM key is refused"):
    val codec = EngineCodec(Engine())
    val resp = ujson.read(
      codec.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"responder","pqRequired":true}}"""
      )
    )
    assert(resp("error")("code").str == "pq_prekey_required")

  test("PQ-INTENT BINDING over the JSON boundary: pqRequired flips the safety number"):
    val ca = EngineCodec(Engine())
    val cb = EngineCodec(Engine())
    val classical = ujson.read(
      ca.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"responder"}}"""
      )
    )
    val required = ujson.read(
      cb.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"initiator","pqRequired":true}}"""
      )
    )
    assert(
      classical("result")("safetyNumber").str != required("result")("safetyNumber").str,
      "pqRequired must bind into the wire-visible safety number"
    )
