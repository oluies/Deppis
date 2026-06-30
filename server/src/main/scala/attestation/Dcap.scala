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
  def ecdsaVerify(
      publicKeyDer: Array[Byte],
      message: Array[Byte],
      signature: Array[Byte]
  ): Boolean =
    try
      val pub = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyDer))
      val sig = Signature.getInstance("SHA256withECDSA")
      sig.initVerify(pub)
      sig.update(message)
      sig.verify(signature)
    // Any malformed-key/signature failure ⇒ not valid (fail closed, no secret-dependent path).
    // `NonFatal` lets fatal/control throwables (OOM, interrupt) propagate rather than be masked.
    catch case NonFatal(_) => false

  /** Wire serialization of a FULL quote (signed body ‖ length-prefixed signature) for transport as
    * the DCAP `evidence` blob. `parseQuote` is the inverse and returns `None` on any malformed/short
    * input (fail closed — a relying party must not appraise a quote it couldn't parse). In production
    * `evidence` is the Intel SGX quote-v3 binary; this length-prefixed form stands in for it on the
    * dev path while preserving the exact `(measurement ‖ key ‖ nonce ‖ signature)` binding. */
  def serializeQuote(q: Quote): Array[Byte] = quoteBody(q) ++ lp(q.signature.toArray)

  /** Wire serialization of a `Measurement` (`mrEnclave ‖ mrSigner`, length-prefixed) — the transparency
    * reference values a relying party pins; `parseMeasurement` is the inverse (None on malformed). */
  def serializeMeasurement(m: Measurement): Array[Byte] =
    lp(m.mrEnclave.toArray) ++ lp(m.mrSigner.toArray)

  def parseMeasurement(bytes: Array[Byte]): Option[Measurement] =
    readLps(bytes, 2) match
      case Some(Seq(me, ms)) => Some(Measurement(me.toVector, ms.toVector))
      case _ => None

  def parseQuote(bytes: Array[Byte]): Option[Quote] =
    readLps(bytes, 5) match
      case Some(Seq(me, ms, key, nonce, sig)) =>
        Some(
          Quote(Measurement(me.toVector, ms.toVector), key.toVector, nonce.toVector, sig.toVector)
        )
      case _ => None

  /** Read exactly `n` length-prefixed (4-byte big-endian length ‖ bytes) fields, requiring the input
    * to be consumed exactly. Bounds-checked at every step; any overflow/underflow ⇒ `None`. */
  private def readLps(b: Array[Byte], n: Int): Option[Seq[Array[Byte]]] =
    val out = scala.collection.mutable.ArrayBuffer.empty[Array[Byte]]
    var off = 0
    var ok = true
    var i = 0
    while ok && i < n do
      // Overflow-safe bounds: subtract from `b.length` (never overflows, since 0 <= off <= b.length)
      // rather than add to `off`. A crafted length prefix (e.g. `7F FF FF FF`) must fail closed to
      // `None`, never wrap to a negative index and throw — the documented fail-closed contract.
      if off > b.length - 4 then ok = false
      else
        val len =
          ((b(off) & 0xff) << 24) | ((b(off + 1) & 0xff) << 16) |
            ((b(off + 2) & 0xff) << 8) | (b(off + 3) & 0xff)
        off += 4
        if len < 0 || len > b.length - off then ok = false
        else { out += b.slice(off, off + len); off += len }
      i += 1
    if ok && off == b.length then Some(out.toSeq) else None

  private def lp(b: Array[Byte]): Array[Byte] = intBytes(b.length) ++ b
  private def intBytes(v: Int): Array[Byte] =
    Array(
      ((v >> 24) & 0xff).toByte,
      ((v >> 16) & 0xff).toByte,
      ((v >> 8) & 0xff).toByte,
      (v & 0xff).toByte
    )

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
