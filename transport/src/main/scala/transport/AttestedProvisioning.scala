package transport

import attestation.{AttestationGate, AttestationVerifier, Quote, ReferenceValues}
import metadatamessenger.store.v1.{store as spb}
import metadatamessenger.notify.v1.{notify as npb}

/** The enclave-target fronts produced by a passing, attested provisioning, plus the verified enclave
  * public key. `attested` is the real result of the attestation gate — `metadataPrivate` on the
  * fronts is `true` ONLY when it is (Constitution IV/IX). */
final case class AttestedFronts(
    storeFront: EnclaveObliviousStore,
    notifyFront: EnclaveNotificationClient, // `notify` would clash with Object.notify()
    enclavePublicKey: Vector[Byte],
    attested: Boolean
)

/** Attestation-gated provisioning of the enclave-target fronts (T058).
  *
  * This is the seam the rest of the system was missing: today every `EnclaveObliviousStore` /
  * `EnclaveNotificationClient` is constructed with `attested = false` (dev), so `metadataPrivate` can
  * never be true. Here we run [[attestation.AttestationGate.provision]] and flow its real `attested`
  * flag — `true` only when a **hardware-backed** verifier vouched for a **passing** quote — into the
  * fronts, so the labeling rule (`Privacy.BuildPrivacyStatus`) flips `metadataPrivate` to `true`
  * exactly and only on a genuine attestation. On a failed attestation, NO fronts are built and NO key
  * is released (returns the gate's fixed, non-secret reason).
  *
  * What is real here: the appraisal + ECDSA-P256 quote-signature core (`DcapAttestationVerifier`),
  * tested with synthetic quotes. What remains TEE/ops-gated (documented, not faked): producing a real
  * SGX quote, the Intel PCK-chain/TCB collateral, the external RATS/Veraison verifier service and the
  * `attestation.proto` gRPC relying-party front (T055/T056), and the live OpenBao Shamir-unseal +
  * transit-wrap that releases the sealed key to the attested enclave key. */
object AttestedProvisioning:
  def provision(
      verifier: AttestationVerifier,
      quote: Quote,
      expectedNonce: Vector[Byte],
      refs: ReferenceValues,
      storeStub: spb.ObliviousStoreGrpc.ObliviousStoreBlockingStub,
      notifyStub: npb.NotificationServiceGrpc.NotificationServiceBlockingStub
  ): Either[String, AttestedFronts] =
    AttestationGate.provision(verifier, quote, expectedNonce, refs).map { p =>
      AttestedFronts(
        storeFront = new EnclaveObliviousStore(storeStub, p.attested),
        notifyFront = new EnclaveNotificationClient(notifyStub, p.attested),
        enclavePublicKey = p.enclavePublicKey,
        attested = p.attested
      )
    }
