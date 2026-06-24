package attestation

import org.scalatest.funsuite.AnyFunSuite

class AttestationSpec extends AnyFunSuite:

  private def bytes(xs: Int*): Vector[Byte] = xs.map(_.toByte).toVector

  private val mrEnclave = bytes(1, 2, 3, 4)
  private val mrSigner = bytes(9, 9, 9)
  private val measure = Measurement(mrEnclave, mrSigner)
  private val refs = ReferenceValues(Set(measure))
  // >= MinNonceBytes (16) so the freshness guard passes; replay defence leans on this.
  private val nonce = (0 until 16).map(i => (0xa0 + i).toByte).toVector
  private val enclaveKey = bytes(0x42, 0x43, 0x44)

  private def quote(
      m: Measurement = measure,
      key: Vector[Byte] = enclaveKey,
      n: Vector[Byte] = nonce
  ): Quote = Quote(m, key, n, signature = bytes(0xde, 0xad))

  /** Test-only verifier with a controllable signature check, so the hardware-backed (privacy-
    * positive) path and the signature-reject path can both be exercised without a TEE. */
  private final class TestVerifier(sigOk: Boolean, hw: Boolean) extends AppraisingVerifier:
    def hardwareBacked: Boolean = hw
    protected def signatureValid(q: Quote): Boolean = sigOk

  test("good quote passes appraisal and releases the enclave key"):
    val r = SoftwareAttestationVerifier().verify(quote(), nonce, refs)
    r match
      case AttestationResult.Passed(m, key) =>
        assert(m == measure)
        assert(key == enclaveKey)
      case other => fail(s"expected Passed, got $other")

  test("dev/software verifier NEVER yields a privacy-positive attested flag (Constitution IV)"):
    val out = AttestationGate.provision(SoftwareAttestationVerifier(), quote(), nonce, refs)
    assert(out.isRight)
    assert(out.toOption.get.attested === false)
    assert(out.toOption.get.enclavePublicKey == enclaveKey)

  test("hardware-backed verifier yields attested=true on a passing quote"):
    val out =
      AttestationGate.provision(new TestVerifier(sigOk = true, hw = true), quote(), nonce, refs)
    assert(out === Right(ProvisionedEnclave(enclaveKey, attested = true)))

  test("freshness nonce mismatch is rejected (replay protection)"):
    // A quote bound to an old nonce cannot be replayed against a fresh expected nonce.
    val stale = quote(n = bytes(1, 1, 1, 1))
    val r = SoftwareAttestationVerifier().verify(stale, expectedNonce = nonce, refs)
    assert(r == AttestationResult.Failed(AttestationResult.NonceMismatch))

  test("invalid quote signature is rejected"):
    val r = new TestVerifier(sigOk = false, hw = true).verify(quote(), nonce, refs)
    assert(r == AttestationResult.Failed(AttestationResult.SignatureInvalid))

  test("measurement outside the transparency-logged reference set is rejected"):
    val foreign = quote(m = Measurement(bytes(7, 7, 7), mrSigner))
    val r = SoftwareAttestationVerifier().verify(foreign, nonce, refs)
    assert(r == AttestationResult.Failed(AttestationResult.MeasurementUntrusted))

  test("a quote with no enclave key is rejected (no key before attestation)"):
    val keyless = quote(key = Vector.empty)
    val r = SoftwareAttestationVerifier().verify(keyless, nonce, refs)
    assert(r == AttestationResult.Failed(AttestationResult.MissingKey))

  test("provision surfaces the fixed failure reason, never secret-dependent detail"):
    val out =
      AttestationGate.provision(SoftwareAttestationVerifier(), quote(n = bytes(0)), nonce, refs)
    assert(out === Left(AttestationResult.NonceMismatch))

  test("a too-short expected nonce is rejected outright (replay-protection guard)"):
    // A degenerate nonce must not silently pass; an empty/short one is rejected before appraisal.
    val short = SoftwareAttestationVerifier().verify(quote(n = Vector.empty), Vector.empty, refs)
    assert(short == AttestationResult.Failed(AttestationResult.WeakNonce))
    val out = AttestationGate.provision(
      SoftwareAttestationVerifier(),
      quote(),
      expectedNonce = bytes(1, 2, 3),
      refs
    )
    assert(out === Left(AttestationResult.WeakNonce))

  test("signature is verified before the body is appraised (bad sig wins over bad nonce)"):
    // Wrong nonce AND bad signature → SignatureInvalid, proving the body is authenticated first.
    val r =
      new TestVerifier(sigOk = false, hw = true).verify(quote(n = bytes(7, 7, 7, 7)), nonce, refs)
    assert(r == AttestationResult.Failed(AttestationResult.SignatureInvalid))

  test("constant-time nonce compare agrees with value equality"):
    assert(Attestation.constTimeEq(nonce, nonce))
    assert(!Attestation.constTimeEq(nonce, nonce.updated(0, 0.toByte)))
    assert(!Attestation.constTimeEq(nonce, nonce.drop(1))) // length differs
