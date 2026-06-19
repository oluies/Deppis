package attestation

/** DEV verifier — **not** a real attestation.
  *
  * It performs the real appraisal (freshness-nonce binding, measurement appraisal against the
  * transparency-logged reference set, key release) but does NOT cryptographically verify the DCAP
  * quote signature — that requires an SGX TEE and Intel collateral (see [[DcapAttestationVerifier]]).
  *
  * Because [[hardwareBacked]] is `false`, [[AttestationGate]] will NEVER mark a backend verified by
  * this class as `attested`/privacy-positive, so a dev build keeps the `DEV, NO METADATA PRIVACY`
  * label even when the appraisal passes (Constitution IV/IX). Use it for development and to test the
  * provisioning flow with synthetic quotes. */
final class SoftwareAttestationVerifier extends AppraisingVerifier:
  def hardwareBacked: Boolean = false

  // DEV: the quote signature is trusted, not verified. A real deployment MUST NOT do this.
  protected def signatureValid(quote: Quote): Boolean = true

/** Production verifier placeholder. Real DCAP quote-signature verification (PCK cert chain, TCB
  * appraisal, QE identity) requires an SGX TEE + Intel collateral and is out of scope until the
  * hardware is available. When implemented, `hardwareBacked` is `true` so a passing appraisal
  * legitimately yields `attested = true`. Left abstract on purpose: instantiating an unverified
  * "hardware" verifier must be a deliberate, reviewed act, not a default. */
abstract class DcapAttestationVerifier extends AppraisingVerifier:
  final def hardwareBacked: Boolean = true
  // protected def signatureValid(quote: Quote): Boolean = <verify DCAP quote vs Intel collateral>
