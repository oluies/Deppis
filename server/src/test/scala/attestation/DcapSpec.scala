package attestation

import java.security.{KeyPairGenerator, SecureRandom, Signature}
import java.security.spec.ECGenParameterSpec
import org.scalatest.funsuite.AnyFunSuite

/** DCAP ECDSA-P256 quote-signature verification, exercised with SYNTHETIC quotes: we generate a
  * real EC P-256 keypair (standing in for the platform attestation key), build a quote, sign its
  * canonical body, and verify. This proves the cryptographic core that `SoftwareAttestationVerifier`
  * stubs; the Intel quote-binary parse + PCK-chain/TCB appraisal that supplies the attestation key
  * is TEE-/collateral-gated (see `design/dcap-attestation.md`). */
class DcapSpec extends AnyFunSuite:

  private def bytes(xs: Int*): Vector[Byte] = xs.map(_.toByte).toVector
  private val mrEnclave = bytes(1, 2, 3, 4)
  private val mrSigner  = bytes(9, 9, 9)
  private val refs = ReferenceValues(Set(mrEnclave), Set(mrSigner))
  private val nonce      = (0 until 16).map(i => (0xa0 + i).toByte).toVector
  private val enclaveKey = bytes(0x42, 0x43, 0x44)

  /** A keypair + a quote signed with it (the attestation key signs `Dcap.quoteBody`). */
  private def signedQuote(): (Array[Byte], Quote) =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom())
    val kp = kpg.generateKeyPair()
    val unsigned = Quote(Measurement(mrEnclave, mrSigner), enclaveKey, nonce, signature = Vector.empty)
    val sig = Signature.getInstance("SHA256withECDSA")
    sig.initSign(kp.getPrivate); sig.update(Dcap.quoteBody(unsigned))
    val signed = unsigned.copy(signature = sig.sign.toVector)
    (kp.getPublic.getEncoded, signed)

  test("a correctly-signed quote passes DCAP verification + the gate yields attested = true"):
    val (pubDer, quote) = signedQuote()
    val v = new DcapAttestationVerifier(pubDer)
    assert(v.hardwareBacked)
    v.verify(quote, nonce, refs) match
      case AttestationResult.Passed(m, k) => assert(m.mrEnclave == mrEnclave && k == enclaveKey)
      case other                          => fail(s"expected Passed, got $other")
    val out = AttestationGate.provision(v, quote, nonce, refs)
    assert(out == Right(ProvisionedEnclave(enclaveKey, attested = true)))

  test("a quote signed by a DIFFERENT key is rejected (signature invalid)"):
    val (_, quote)   = signedQuote()
    val (otherKey, _) = signedQuote() // unrelated keypair
    val v = new DcapAttestationVerifier(otherKey)
    assert(v.verify(quote, nonce, refs) == AttestationResult.Failed(AttestationResult.SignatureInvalid))

  test("a tampered measurement breaks the signature (the quote body changed)"):
    val (pubDer, quote) = signedQuote()
    val tampered = quote.copy(measurement = Measurement(bytes(7, 7, 7, 7), mrSigner))
    val v = new DcapAttestationVerifier(pubDer)
    // The reference set would also reject it, but the signature check fails first / regardless.
    assert(v.verify(tampered, nonce, refs).isInstanceOf[AttestationResult.Failed])

  test("a tampered enclave key breaks the signature (key substitution defeated)"):
    val (pubDer, quote) = signedQuote()
    val swapped = quote.copy(enclavePublicKey = bytes(0x00, 0x00))
    val v = new DcapAttestationVerifier(pubDer)
    assert(v.verify(swapped, nonce, refs) == AttestationResult.Failed(AttestationResult.SignatureInvalid))

  test("a garbage attestation key is rejected, not thrown"):
    val (_, quote) = signedQuote()
    val v = new DcapAttestationVerifier(Array[Byte](1, 2, 3)) // not a valid X.509 EC key
    assert(v.verify(quote, nonce, refs) == AttestationResult.Failed(AttestationResult.SignatureInvalid))

  test("Dcap.quoteBody binds measurement, key, and nonce (changing any changes the body)"):
    val q = Quote(Measurement(mrEnclave, mrSigner), enclaveKey, nonce, Vector.empty)
    val base = Dcap.quoteBody(q).toVector
    assert(Dcap.quoteBody(q.copy(nonce = nonce.updated(0, 0.toByte))).toVector != base)
    assert(Dcap.quoteBody(q.copy(enclavePublicKey = bytes(1))).toVector != base)
    assert(Dcap.quoteBody(q.copy(measurement = Measurement(bytes(0), mrSigner))).toVector != base)
