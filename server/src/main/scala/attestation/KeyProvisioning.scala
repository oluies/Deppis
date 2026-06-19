package attestation

/** Result of attestation-gated provisioning: the verified enclave public key plus whether the
  * backend may claim metadata privacy. `attested` is true ONLY when a hardware-backed verifier
  * vouched for a passing quote — it is exactly the boolean the enclave-target fronts
  * (`EnclaveNotificationClient`, `EnclaveObliviousStore`) consume to derive their privacy label
  * via `Privacy.BuildPrivacyStatus`. */
final case class ProvisionedEnclave(enclavePublicKey: Vector[Byte], attested: Boolean)

/** The attestation gate (Constitution IX, research D11).
  *
  * Models the secret-release boundary: a long-term root key is held by an external sealed store
  * (OpenBao, unsealed via Shamir shares — see `design/attestation-key-provisioning.md`), and the
  * sealed PONG/notify key is unwrapped to the enclave ONLY after a passing remote-attestation
  * result. Here that boundary is the function below: the enclave public key is returned ONLY on a
  * passing quote, and the backend is marked `attested` ONLY when the verifier is hardware-backed.
  *
  * A fresh `expectedNonce` MUST be minted per provisioning attempt and never reused, so a captured
  * quote cannot be replayed (the nonce is bound into the signed quote body). */
object AttestationGate:

  def provision(
      verifier: AttestationVerifier,
      quote: Quote,
      expectedNonce: Vector[Byte],
      refs: ReferenceValues
  ): Either[String, ProvisionedEnclave] =
    verifier.verify(quote, expectedNonce, refs) match
      case AttestationResult.Passed(_, key) =>
        Right(ProvisionedEnclave(key, attested = verifier.hardwareBacked))
      case AttestationResult.Failed(reason) =>
        Left(reason)
