package transport

import metadatamessenger.attestation.v1.attestation.*
import metadatamessenger.attestation.v1.attestation.AttestationServiceGrpc.{
  AttestationService,
  AttestationServiceBlockingStub
}
import attestation.{
  AttestationGate,
  AttestationResult,
  DcapAttestationVerifier,
  Dcap,
  Measurement,
  ProvisionedEnclave,
  Quote,
  ReferenceValues
}
import com.google.protobuf.ByteString
import java.security.{MessageDigest, PrivateKey, SecureRandom, Signature}
import scala.concurrent.Future
import scala.util.control.NonFatal

/** gRPC `AttestationService` front + relying-party client (T056, contract `attestation.proto`,
  * Constitution IX — Attestation, Not Identity).
  *
  * On `Attest(client_nonce)` the enclave produces **evidence** — a DCAP quote binding the freshness
  * nonce, the enclave measurement, and the enclave's ephemeral public key — and returns it for the
  * RELYING PARTY to appraise under its OWN pinned policy (the attestation key it trusts + the
  * transparency-logged reference values). The enclave public key is accepted ONLY after the client
  * verifies the evidence signature + nonce echo + measurement; trust never derives from service
  * identity (a TLS/SPIFFE cert is not a substitute).
  *
  * WHAT IS REAL HERE (CI-tested in-process with synthetic quotes): the round-trip provisioning seam,
  * the client-side appraisal (real ECDSA-P256 over the quote body via [[DcapAttestationVerifier]]),
  * nonce-freshness binding, measurement appraisal against pinned references, and the privacy-gating
  * rule (`metadataPrivate` follows the verifier's `hardwareBacked`).
  *
  * WHAT IS HARDWARE/COLLATERAL-GATED: the real Intel SGX quote-v3 binary produced by a genuine
  * enclave, the PCK-chain/TCB endorsement of the attestation key, and an external Veraison/RATS
  * verifier issuing a signed `verifier_result`. The dev path signs the quote with a software EC key
  * standing in for the platform key; because that key is NOT PCK-endorsed, a client that pins it does
  * so as a deliberate dev act and `metadataPrivate` follows `hardwareBacked` — never silently set. */
final class AttestationServiceImpl(
    measurement: Measurement,
    enclavePublicKey: Array[Byte],
    attestationSigner: PrivateKey, // signs the quote body — dev stand-in for the platform attestation key
    referenceValues: Seq[Measurement]
) extends AttestationService:

  def attest(req: AttestRequest): Future[AttestResponse] =
    // Bind the client's nonce into the (synthetic) DCAP quote body and sign it. A real quoting enclave
    // does this in hardware with the platform key; here we sign `Dcap.quoteBody` with the dev EC key.
    val nonce = req.clientNonce.toByteArray.toVector
    val unsigned = Quote(measurement, enclavePublicKey.toVector, nonce, signature = Vector.empty)
    val sig = Signature.getInstance("SHA256withECDSA")
    sig.initSign(attestationSigner)
    sig.update(Dcap.quoteBody(unsigned))
    val quote = unsigned.copy(signature = sig.sign.toVector)
    Future.successful(
      AttestResponse(
        evidence = ByteString.copyFrom(Dcap.serializeQuote(quote)),
        echoedNonce = req.clientNonce,
        enclavePublicKey = ByteString.copyFrom(enclavePublicKey),
        referenceValues =
          referenceValues.map(m => ByteString.copyFrom(Dcap.serializeMeasurement(m)))
        // verifier_result / verifier_signature: in the background-check (Veraison) model these carry a
        // verifier's signed appraisal. The relying-party client below re-appraises the evidence under
        // its own pinned policy, so they are left empty on the dev path (a real front populates them).
      )
    )

/** Relying party: remotely provisions the enclave and appraises its evidence under a PINNED policy. */
final class AttestationProvisioningClient(
    stub: AttestationServiceBlockingStub,
    pinnedAttestationKeyDer: Array[
      Byte
    ], // the attestation key the client trusts (PCK-endorsed in prod)
    pinnedReferenceValues: ReferenceValues, // transparency-logged measurements the client accepts
    rng: SecureRandom = new SecureRandom
):

  /** Mint a FRESH nonce, fetch evidence, and appraise it under the pinned policy. Returns the verified
    * enclave key + whether the backend may claim metadata privacy. The key is accepted ONLY on a
    * passing, hardware-backed appraisal; a `Left` reason is fixed/non-secret (Constitution II). */
  def provision(): Either[String, ProvisionedEnclave] =
    val nonce = new Array[Byte](AttestationResult.MinNonceBytes)
    rng.nextBytes(nonce)
    try
      val resp = stub.attest(AttestRequest(clientNonce = ByteString.copyFrom(nonce)))
      // The result MUST echo our nonce (constant-time) — else a replayed/stale quote could be accepted.
      if !MessageDigest.isEqual(resp.echoedNonce.toByteArray, nonce) then
        Left("attestation: freshness nonce not echoed")
      else
        Dcap.parseQuote(resp.evidence.toByteArray) match
          case None => Left("attestation: unparseable evidence")
          case Some(quote) =>
            // Appraise under OUR pinned policy: real ECDSA over the quote body against the pinned
            // attestation key, nonce binding, and measurement membership in the pinned reference set.
            AttestationGate.provision(
              new DcapAttestationVerifier(pinnedAttestationKeyDer),
              quote,
              nonce.toVector,
              pinnedReferenceValues
            )
    catch case NonFatal(_) => Left("attestation: provisioning rpc failed")
