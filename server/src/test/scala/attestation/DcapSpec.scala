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

  // ---- Fixed known-answer vectors (independent of the round trip) ----

  private def hex(s: String): Array[Byte] = s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  test("KAT: quoteBody encoding is the exact pinned length-prefixed layout"):
    // measurement mrEnclave=[1,2,3], mrSigner=[9,9], key=[7,7,7], nonce=[5,5].
    val q = Quote(Measurement(bytes(1, 2, 3), bytes(9, 9)), bytes(7, 7, 7), bytes(5, 5), Vector.empty)
    val got = Dcap.quoteBody(q).map(b => f"${b & 0xff}%02x").mkString
    assert(got == "0000000301020300000002090900000003070707000000020505")

  test("KAT: a fixed (P-256 key, message, signature) verifies — pins SHA256withECDSA on secp256r1"):
    // A static vector (generated once); a wrong digest or curve would fail to verify it, catching a
    // silently mis-wired primitive that a fresh-keypair round trip cannot.
    val pub = hex(
      "3059301306072a8648ce3d020106082a8648ce3d03010703420004dad972985a5b637b8303a795b5da5dfa" +
        "17004c9e35c4001e406282ace9a23f0e1a12918633dc8e89143031634aaafb39edf333d90f513043790808bd44bb02f3")
    val sig = hex(
      "304502210084630a93695212d64287177a341194e5cbe42c573fc584dcdd2a8e1a91adba50022060100b6fd" +
        "e596c5e7afbc196d9d4a49a2ea8d1f4400d41658224e2038ccde551")
    val msg = "dcap-kat-message".getBytes("UTF-8")
    assert(Dcap.ecdsaVerify(pub, msg, sig), "the pinned vector must verify")
    assert(!Dcap.ecdsaVerify(pub, msg, sig.updated(sig.length - 1, (sig.last ^ 0x01).toByte)), "flip ⇒ reject")
    assert(!Dcap.ecdsaVerify(pub, "different".getBytes("UTF-8"), sig), "wrong message ⇒ reject")
