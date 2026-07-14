package engine

import org.scalatest.funsuite.AnyFunSuite

/** SINGLE-SOURCED cross-platform test (compiled into BOTH the JVM `protocolCore` and the Scala.js
  * `protocolCoreJS` builds — see build.sbt) that drives the REFLECTION attack through the engine on
  * both platforms, pinning the anti-reflection guarantee of bidirectional PQ key confirmation (US7).
  *
  * The two confirmation tags are DOMAIN-SEPARATED (`"ks/pq-confirm/r"` vs `"ks/pq-confirm/i"`), so a
  * tag observed in transit for one direction can never satisfy the other direction's constant-time
  * check. An attacker who reflects the responder's `/r` tag (which it sees on the wire) back as the
  * initiator's tag must NOT confirm the responder, and a `/i`-domain tag presented where a `/r` tag is
  * expected must NOT confirm the initiator — otherwise a single observed tag would let a MITM confirm a
  * side without ever breaking the KEM. */
class PqReflectionCrossSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")

  /** One PQ pairing carried to the point where both tags exist: the responder's `/r` tag (from
    * `addBuddy`) and the initiator's `/i` tag (from its completion), BOTH over the same `rootP`. */
  private def bothTags(): (Engine, String, Array[Byte], Array[Byte]) =
    val alice = Engine()
    val bob = Engine()
    val aRes =
      alice.addBuddy(secret("oob"), BuddyRole.Initiator, initiatePqPrekey = true).toOption.get
    val bRes = bob
      .addBuddy(secret("oob"), BuddyRole.Responder, initiatorKemPublicKey = aRes.kemPublicKey)
      .toOption
      .get
    val rTag = bRes.kemConfirmTag.get // the responder's /r tag — observable in transit
    val iTag = alice
      .confirmBuddy(
        aRes.pairId,
        matched = true,
        kemCiphertext = bRes.kemCiphertext,
        kemConfirmTag = bRes.kemConfirmTag
      )
      .toOption
      .get
      .initiatorConfirmTag
      .get // the initiator's /i tag over the SAME rootP
    (bob, aRes.pairId, rTag, iTag)

  test("REFLECTION: the /r and /i tags of one rootP differ (domain separation, no reflection)"):
    val (_, _, rTag, iTag) = bothTags()
    assert(!rTag.sameElements(iTag), "distinct labels ⇒ the two directions' tags must differ")

  test("REFLECTION: the RESPONDER rejects its OWN /r tag reflected as the initiator tag"):
    val (bob, pid, rTag, iTag) = bothTags()
    // Attacker reflects the /r tag (seen on the wire) back as `initiatorConfirmTag`: the responder
    // expects the /i tag, so the constant-time compare fails closed.
    assert(
      bob.confirmBuddy(pid, matched = true, initiatorConfirmTag = Some(rTag)) ==
        Left(EngineError("pq_confirm_failed", "KEM key confirmation failed"))
    )
    assert(bob.confirmedCount == 0, "a reflected /r tag must not confirm the responder")
    assert(bob.drainEvents().isEmpty, "no BuddyConfirmed on a reflected tag")
    // Sanity: the guard is domain-specific, not blanket — the genuine /i tag DOES confirm the responder.
    assert(bob.confirmBuddy(pid, matched = true, initiatorConfirmTag = Some(iTag)).isRight)
    assert(bob.confirmedCount == 1)

  test(
    "REFLECTION: the INITIATOR rejects a /i-domain tag presented as the responder's kemConfirmTag"
  ):
    // A `/i`-domain tag (from a real pairing) fed where the initiator expects the responder's `/r` tag:
    // the initiator's constant-time /r compare fails closed (a /i value never satisfies a /r check).
    val (_, _, _, iTag) = bothTags()
    val alice = Engine()
    val bob = Engine()
    val aRes =
      alice.addBuddy(secret("oob"), BuddyRole.Initiator, initiatePqPrekey = true).toOption.get
    val bRes = bob
      .addBuddy(secret("oob"), BuddyRole.Responder, initiatorKemPublicKey = aRes.kemPublicKey)
      .toOption
      .get
    assert(
      alice.confirmBuddy(
        aRes.pairId,
        matched = true,
        kemCiphertext = bRes.kemCiphertext,
        kemConfirmTag = Some(iTag)
      ) == Left(EngineError("pq_confirm_failed", "KEM key confirmation failed"))
    )
    assert(alice.confirmedCount == 0, "a /i-domain tag must not confirm the initiator")
    // The parked prekey is retained ⇒ the genuine /r tag still completes.
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
