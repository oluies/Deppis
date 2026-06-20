package attestation

import java.security.{KeyFactory, Signature}
import java.security.spec.X509EncodedKeySpec
import scala.util.control.NonFatal

/** DCAP (Intel SGX ECDSA) attestation — the cryptographic quote-signature verification.
  *
  * A real SGX DCAP quote binds the enclave **measurement** (`mrEnclave`/`mrSigner`), the enclave's
  * ephemeral key + the verifier nonce (the SGX report-data field), and is **ECDSA-P256 signed by the
  * platform attestation key**, which is in turn endorsed by Intel's PCK certificate chain. This
  * module verifies the signature over that binding — the load-bearing cryptographic step that
  * [[SoftwareAttestationVerifier]] only stubs.
  *
  * WHAT IS REAL HERE (and CI-tested with synthetic quotes):
  *   - the canonical quote-body encoding that the signature covers (measurement ‖ key ‖ nonce);
  *   - ECDSA-P256 (`SHA256withECDSA`) verification against the endorsed attestation public key;
  *   - composition with [[AppraisingVerifier]] (nonce/measurement/key appraisal) + the
  *     [[AttestationGate]] (`hardwareBacked = true` ⇒ a passing quote yields `attested = true`).
  *
  * WHAT IS TEE-/COLLATERAL-GATED (see `design/dcap-attestation.md`):
  *   - parsing the Intel SGX **quote v3 binary** (header ‖ ISV report ‖ signature section ‖ QE
  *     report ‖ cert data) into these fields;
  *   - verifying the attestation key's endorsement through the **PCK cert chain to the Intel SGX
  *     Root CA**, and appraising **TCB** (TCBInfo + QEIdentity from the Intel PCS) with advisory/
  *     freshness handling. This `DcapAttestationVerifier` takes the endorsed attestation key as a
  *     constructor input — in production that key comes from the verified PCK chain, NOT a config. */
object Dcap:
  /** The deterministic bytes the platform attestation key signs: a length-prefixed encoding of the
    * measurement, the enclave public key, and the freshness nonce. Both the (real) quoting enclave
    * and this verifier compute it identically, so the signature binds exactly these fields. */
  def quoteBody(q: Quote): Array[Byte] =
    lp(q.measurement.mrEnclave.toArray) ++ lp(q.measurement.mrSigner.toArray) ++
      lp(q.enclavePublicKey.toArray) ++ lp(q.nonce.toArray)

  /** Verify an ECDSA-P256 signature (`SHA256withECDSA`, X.509-encoded public key). */
  def ecdsaVerify(publicKeyDer: Array[Byte], message: Array[Byte], signature: Array[Byte]): Boolean =
    try
      val pub = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyDer))
      val sig = Signature.getInstance("SHA256withECDSA")
      sig.initVerify(pub)
      sig.update(message)
      sig.verify(signature)
    // Any malformed-key/signature failure ⇒ not valid (fail closed, no secret-dependent path).
    // `NonFatal` lets fatal/control throwables (OOM, interrupt) propagate rather than be masked.
    catch case NonFatal(_) => false

  private def lp(b: Array[Byte]): Array[Byte] = intBytes(b.length) ++ b
  private def intBytes(v: Int): Array[Byte] =
    Array(((v >> 24) & 0xff).toByte, ((v >> 16) & 0xff).toByte, ((v >> 8) & 0xff).toByte, (v & 0xff).toByte)

/** Production attestation verifier: real ECDSA-P256 quote-signature verification (Constitution IX).
  *
  * `hardwareBacked = true`, so a passing appraisal legitimately yields `attested = true` and the
  * backend may claim metadata privacy. `attestationKeyDer` is the platform attestation public key —
  * in production obtained from the **PCK-endorsed** chain after TCB appraisal (gated); supplying an
  * unendorsed key here is a deliberate, reviewed act. The `Quote.signature` field carries the
  * ECDSA-P256 signature over [[Dcap.quoteBody]]. */
final class DcapAttestationVerifier(attestationKeyDer: Array[Byte]) extends AppraisingVerifier:
  def hardwareBacked: Boolean = true

  protected def signatureValid(quote: Quote): Boolean =
    Dcap.ecdsaVerify(attestationKeyDer, Dcap.quoteBody(quote), quote.signature.toArray)
