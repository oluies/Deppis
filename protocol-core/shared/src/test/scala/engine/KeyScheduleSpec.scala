package engine

import org.scalatest.funsuite.AnyFunSuite

/** The forward-secret symmetric ratchet's key schedule. Pins the properties that make the message
  * path forward-secret: independent roots, a forward-only chain with no key reuse, and cross-party
  * agreement. The engine round-trip (RoundTransportSpec) proves the chains stay in lockstep. */
class KeyScheduleSpec extends AnyFunSuite:

  private def pk: Array[Byte] = Array.tabulate(32)(i => (i * 7 + 1).toByte)

  test("addrKey and contentRoot are independent roots, both deterministic from the pair key"):
    assert(!KeySchedule.addrKey(pk).sameElements(KeySchedule.contentRoot(pk)))
    // Deterministic: the two parties derive the same roots from the same out-of-band secret.
    assert(KeySchedule.addrKey(pk).sameElements(KeySchedule.addrKey(pk.clone())))
    assert(KeySchedule.contentRoot(pk).sameElements(KeySchedule.contentRoot(pk.clone())))

  test("a message key is exactly the AEAD key size (32 bytes)"):
    val ck = KeySchedule.chain0(KeySchedule.contentRoot(pk), "Initiator", "Responder")
    assert(KeySchedule.messageKey(ck).length == aead.Aead.KeyBytes)

  test("the chain ratchets forward — every position yields a DISTINCT message key (no reuse)"):
    var ck = KeySchedule.chain0(KeySchedule.contentRoot(pk), "Initiator", "Responder")
    val keys = (0 until 8).map { _ =>
      val mk = KeySchedule.messageKey(ck).toVector
      ck = KeySchedule.nextChain(ck)
      mk
    }
    assert(
      keys.distinct.size == keys.size
    ) // forward secrecy: a wiped chain key can't reproduce a prior key

  test("the chain key advances on each ratchet step (one-way forward motion)"):
    val ck0 = KeySchedule.chain0(KeySchedule.contentRoot(pk), "Initiator", "Responder")
    val ck1 = KeySchedule.nextChain(ck0)
    val ck2 = KeySchedule.nextChain(ck1)
    assert(!ck0.sameElements(ck1) && !ck1.sameElements(ck2) && !ck0.sameElements(ck2))

  test("opposite directions seed DIFFERENT chains (no cross-direction key reuse)"):
    val cr = KeySchedule.contentRoot(pk)
    // Initiator→Responder and Responder→Initiator are independent chains, so the two directions never
    // share a message key. (The cross-party lockstep — Alice's send chain == Bob's recv chain for a
    // direction — is inherent to the direction naming, so it can't be falsified by comparing two
    // derivations from the same strings; it is exercised behaviorally by the two-engine round-trip in
    // RoundTransportSpec, which only works if the chains stay in lockstep across several messages.)
    assert(
      !KeySchedule
        .chain0(cr, "Initiator", "Responder")
        .sameElements(KeySchedule.chain0(cr, "Responder", "Initiator"))
    )
