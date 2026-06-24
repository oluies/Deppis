package attestation

import org.scalatest.funsuite.AnyFunSuite

/** The reference log ties the transparency log to attestation appraisal (T057): a measurement is in the
  * trusted set ONLY when it is logged AND inclusion-proven against the pinned root, and the appraisal
  * `ReferenceValues` are derived ONLY from the logged measurements. */
class ReferenceLogSpec extends AnyFunSuite:

  private def m(a: Byte, s: Byte): Measurement =
    Measurement(Vector.fill(32)(a), Vector.fill(32)(s))

  test("a logged measurement is trusted; an unlogged one is not"):
    val log = new ReferenceLog
    val good = m(0xaa.toByte, 0x01)
    log.append(m(0x10, 0x20)) // some other entries
    log.append(good)
    log.append(m(0x30, 0x40))
    val pinned = log.root // a relying party pins this published root
    val ref = log.reference(good).getOrElse(fail("good should be logged"))
    assert(ReferenceLogTrust.trusts(ref, log.size, pinned), "logged measurement verifies")
    // A measurement that was never appended has no record at all.
    assert(log.reference(m(0x99.toByte, 0x99.toByte)).isEmpty, "unlogged ⇒ no reference")

  test("an inclusion proof for the WRONG pinned root is rejected (can't forge trust)"):
    val log = new ReferenceLog
    val good = m(0xab.toByte, 0x02)
    log.append(good); log.append(m(0x55, 0x66))
    val ref = log.reference(good).get
    val otherRoot = { val c = log.root.clone(); c(0) = (c(0) ^ 0x01).toByte; c }
    assert(!ReferenceLogTrust.trusts(ref, log.size, otherRoot), "wrong root ⇒ untrusted")

  test(
    "the appraisal ReferenceValues are exactly the logged measurements (verifier set is auditable)"
  ):
    val log = new ReferenceLog
    val a = m(0x01, 0x02); val b = m(0x03, 0x04)
    log.append(a); log.append(b)
    val refs = log.referenceValues
    assert(refs.allowed == Set(a, b), "exactly the logged measurement pairs")
    // And the verifier, fed the log's reference set, passes the logged measurement and rejects others.
    val verifier = new SoftwareAttestationVerifier
    val nonce = Vector.tabulate(16)(i => i.toByte)
    val passed = verifier.verify(Quote(a, Vector(7, 7, 7), nonce, Vector.empty), nonce, refs)
    assert(passed match { case AttestationResult.Passed(_, _) => true; case _ => false })
    val rogue = verifier.verify(
      Quote(m(0x99.toByte, 0x99.toByte), Vector(7), nonce, Vector.empty),
      nonce,
      refs
    )
    assert(rogue match { case AttestationResult.Failed(_) => true; case _ => false })

  test(
    "a never-logged CROSS combination of two logged measurements is rejected (binding preserved)"
  ):
    // (E1,S1) and (E2,S2) logged; the cross (E1,S2) was never logged and must NOT be trusted — the
    // measurement-to-signer binding is preserved (no Cartesian product).
    val log = new ReferenceLog
    val one = Measurement(Vector.fill(32)(0x11), Vector.fill(32)(0x22))
    val two = Measurement(Vector.fill(32)(0x33), Vector.fill(32)(0x44))
    log.append(one); log.append(two)
    val cross = Measurement(one.mrEnclave, two.mrSigner) // E1 ‖ S2 — never logged
    assert(log.reference(cross).isEmpty, "cross combination is not in the log")
    val verifier = new SoftwareAttestationVerifier
    val nonce = Vector.tabulate(16)(i => i.toByte)
    val res =
      verifier.verify(Quote(cross, Vector(1), nonce, Vector.empty), nonce, log.referenceValues)
    assert(
      res match { case AttestationResult.Failed(_) => true; case _ => false },
      "cross ⇒ untrusted"
    )
