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
  // The production verifier is `DcapAttestationVerifier` (real ECDSA-P256 quote-signature checking).
  protected def signatureValid(quote: Quote): Boolean = true
