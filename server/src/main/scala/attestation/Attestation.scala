package attestation

import java.security.MessageDigest

/** Constitution IX — **Attestation, Not Identity** (NON-NEGOTIABLE).
  *
  * On the PING/PONG path, trust MUST derive from a verified attestation result over the enclave,
  * appraised against transparency-logged reference values with a freshness nonce, and NEVER from
  * service identity (a SPIFFE SVID / mesh cert is not a substitute). An enclave public key MUST
  * NOT be accepted before attestation. This module is the verifier + the key-provisioning gate
  * that enforce exactly that: the enclave key is released — and a backend may claim metadata
  * privacy — ONLY after a passing, hardware-backed result.
  *
  * What is real here vs. TEE-gated:
  *   - REAL (and unit-tested with synthetic quotes): freshness-nonce binding, appraisal against
  *     transparency-logged reference measurements, key release, and the privacy-gating rule.
  *   - TEE-GATED (see [[AppraisingVerifier.signatureValid]]): cryptographic verification of the
  *     DCAP quote signature against Intel/platform collateral. That needs real SGX hardware; the
  *     dev [[SoftwareAttestationVerifier]] stubs it and therefore never claims privacy.
  */

/** SGX-style measurements identifying the exact code running in the enclave. `mrEnclave` is the
  * code/data measurement; `mrSigner` identifies the signing key of the enclave image. */
final case class Measurement(mrEnclave: Vector[Byte], mrSigner: Vector[Byte])

/** Attestation evidence produced by the enclave (a DCAP quote in production).
  *
  * The signed body binds `measurement`, the enclave's ephemeral `enclavePublicKey`, and the
  * verifier-supplied freshness `nonce` (carried in the SGX report-data field) so a quote cannot be
  * replayed and the key cannot be substituted. `signature` is the platform attestation signature. */
final case class Quote(
    measurement: Measurement,
    enclavePublicKey: Vector[Byte],
    nonce: Vector[Byte],
    signature: Vector[Byte]
)

/** Transparency-logged reference values the measurement is appraised against (Constitution IX/X):
  * only enclaves whose measurement is in the published, reviewed set are trusted. The set holds whole
  * `(mrEnclave, mrSigner)` measurements (PAIRS), so the `mrEnclave ↔ mrSigner` binding is preserved —
  * appraising the two components against independent sets would accept a never-logged cross
  * combination `(E1, S2)` of two logged measurements `(E1, S1)`, `(E2, S2)`. */
final case class ReferenceValues(allowed: Set[Measurement])

/** Outcome of appraising a quote. `Failed` reasons are fixed, public strings — never
  * secret-dependent (Constitution II). On `Passed`, the verified enclave key is released. */
enum AttestationResult:
  case Passed(measurement: Measurement, enclavePublicKey: Vector[Byte])
  case Failed(reason: String)

object AttestationResult:
  // Fixed, value-independent reasons (Constitution II — logs/errors must not vary on secrets).
  val WeakNonce = "attestation: expected freshness nonce too short"
  val NonceMismatch = "attestation: freshness nonce mismatch"
  val SignatureInvalid = "attestation: quote signature invalid"
  val MeasurementUntrusted =
    "attestation: measurement not in transparency-logged reference set"
  val MissingKey = "attestation: enclave public key absent"

  /** Minimum freshness-nonce length. Replay protection is only as strong as the nonce; an empty or
    * trivially short nonce (a caller misconfiguration) would silently defeat it, so the verifier
    * rejects it outright rather than appraising against a degenerate value. */
  val MinNonceBytes = 16

/** Appraises a quote. Trust derives only from the quote (Constitution IX) — this interface has no
  * notion of, and never consults, service identity. */
trait AttestationVerifier:

  /** True ONLY for a verifier that cryptographically verifies the DCAP quote signature against real
    * platform collateral. A dev/software verifier returns false, so a build can exercise the whole
    * provisioning flow without ever claiming metadata privacy (Constitution IV). */
  def hardwareBacked: Boolean

  /** Appraise `quote` against `refs`, requiring the quote to carry `expectedNonce`. */
  def verify(
      quote: Quote,
      expectedNonce: Vector[Byte],
      refs: ReferenceValues
  ): AttestationResult

/** Shared appraisal logic; the signature-verification step is the only TEE-gated hook. */
abstract class AppraisingVerifier extends AttestationVerifier:

  /** Verify the quote's cryptographic signature over its signed body against platform/provisioning
    * collateral. Real DCAP verification requires an SGX TEE and Intel collateral; the dev verifier
    * trusts it. Implementations MUST be constant-time on the reject path. */
  protected def signatureValid(quote: Quote): Boolean

  final def verify(
      quote: Quote,
      expectedNonce: Vector[Byte],
      refs: ReferenceValues
  ): AttestationResult =
    import AttestationResult.*
    // 1. Reject a degenerate expected nonce (our own misconfiguration) before anything else, so a
    //    weak nonce cannot silently disable replay protection.
    // 2. Verify the signature FIRST: in a real DCAP quote the nonce, measurement, and pubkey all
    //    live inside the signed body, so appraising them is only meaningful once the body is
    //    authenticated. Checking signature first also keeps the reported reason from distinguishing
    //    a nonce match on an unsigned/attacker-controlled quote.
    // 3. Only then appraise the now-authenticated nonce, measurement, and key. These compare
    //    non-secret material (nonce via constant-time compare), so ordering leaks nothing.
    if expectedNonce.length < MinNonceBytes then Failed(WeakNonce)
    else if !signatureValid(quote) then Failed(SignatureInvalid)
    else if !Attestation.constTimeEq(quote.nonce, expectedNonce) then Failed(NonceMismatch)
    else if !appraised(quote.measurement, refs) then Failed(MeasurementUntrusted)
    else if quote.enclavePublicKey.isEmpty then Failed(MissingKey)
    else Passed(quote.measurement, quote.enclavePublicKey)

  /** Measurement appraisal compares against the published reference set. These are public
    * (transparency-logged) values, not secrets, so ordinary set membership is appropriate. */
  private def appraised(m: Measurement, refs: ReferenceValues): Boolean =
    refs.allowed.contains(m) // exact (mrEnclave, mrSigner) pair — no cross-product

object Attestation:
  /** Constant-time equality for the freshness-nonce comparison (Constitution III). Length is not
    * secret; content comparison does not short-circuit on the first differing byte. */
  def constTimeEq(a: Vector[Byte], b: Vector[Byte]): Boolean =
    MessageDigest.isEqual(a.toArray, b.toArray)
