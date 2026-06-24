package transport

import attestation.*
import metadatamessenger.store.v1.{store as spb}
import metadatamessenger.notify.v1.{notify as npb}
import privacy.Privacy
import io.grpc.inprocess.InProcessChannelBuilder
import java.security.{KeyPairGenerator, SecureRandom, Signature}
import java.security.spec.ECGenParameterSpec
import org.scalatest.funsuite.AnyFunSuite

/** T058: the attestation result must flow into the enclave fronts so `metadataPrivate` flips to
  * `true` ONLY on a passing, hardware-backed attestation — and stays `false` (DEV label) otherwise.
  * Uses synthetic quotes (the same machinery `DcapSpec` proves the crypto core with); no SGX. */
class AttestedProvisioningSpec extends AnyFunSuite:

  private def bytes(xs: Int*): Vector[Byte] = xs.map(_.toByte).toVector
  private val mrEnclave = bytes(1, 2, 3, 4)
  private val mrSigner = bytes(9, 9, 9)
  private val refs = ReferenceValues(Set(Measurement(mrEnclave, mrSigner)))
  private val nonce = (0 until 16).map(i => (0xa0 + i).toByte).toVector
  private val enclaveKey = bytes(0x42, 0x43, 0x44)

  /** A platform keypair (DER pubkey) + a quote signed with it over `Dcap.quoteBody`. */
  private def signedQuote(): (Array[Byte], Quote) =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom())
    val kp = kpg.generateKeyPair()
    val unsigned =
      Quote(Measurement(mrEnclave, mrSigner), enclaveKey, nonce, signature = Vector.empty)
    val sig = Signature.getInstance("SHA256withECDSA")
    sig.initSign(kp.getPrivate); sig.update(Dcap.quoteBody(unsigned))
    (kp.getPublic.getEncoded, unsigned.copy(signature = sig.sign.toVector))

  /** Dummy stubs over an unconnected in-process channel — the fronts only need them to exist; these
    * tests assert on `metadataPrivate`/`label`, which don't touch the channel. `body` gets the stubs. */
  private def withStubs(
      body: (
          spb.ObliviousStoreGrpc.ObliviousStoreBlockingStub,
          npb.NotificationServiceGrpc.NotificationServiceBlockingStub
      ) => Unit
  ): Unit =
    val ch = InProcessChannelBuilder.forName("attest-provisioning-test").build()
    try body(spb.ObliviousStoreGrpc.blockingStub(ch), npb.NotificationServiceGrpc.blockingStub(ch))
    finally ch.shutdownNow()

  test("hardware-backed verifier + passing quote ⇒ fronts are METADATA PRIVATE (T058)"):
    val (pubDer, quote) = signedQuote()
    withStubs { (storeStub, notifyStub) =>
      val out = AttestedProvisioning.provision(
        new DcapAttestationVerifier(pubDer),
        quote,
        nonce,
        refs,
        storeStub,
        notifyStub
      )
      val fronts = out.toOption.get
      assert(fronts.attested)
      assert(fronts.enclavePublicKey == enclaveKey)
      assert(fronts.storeFront.metadataPrivate && fronts.notifyFront.metadataPrivate)
      assert(fronts.storeFront.label == Privacy.PrivateLabel)
      assert(fronts.notifyFront.label == Privacy.PrivateLabel)
    }

  test(
    "software (dev) verifier + passing quote ⇒ fronts stay DEV (never private — Constitution IV)"
  ):
    val (_, quote) = signedQuote()
    withStubs { (storeStub, notifyStub) =>
      val fronts = AttestedProvisioning
        .provision(new SoftwareAttestationVerifier, quote, nonce, refs, storeStub, notifyStub)
        .toOption
        .get
      assert(!fronts.attested)
      assert(!fronts.storeFront.metadataPrivate && !fronts.notifyFront.metadataPrivate)
      assert(fronts.storeFront.label == Privacy.DevLabel)
      assert(fronts.notifyFront.label == Privacy.DevLabel)
    }

  test("a failed attestation builds NO fronts and releases NO key (returns the fixed reason)"):
    val (_, quote) = signedQuote()
    val (wrongKey, _) = signedQuote() // unrelated keypair ⇒ signature invalid
    withStubs { (storeStub, notifyStub) =>
      val out = AttestedProvisioning
        .provision(new DcapAttestationVerifier(wrongKey), quote, nonce, refs, storeStub, notifyStub)
      assert(out == Left(AttestationResult.SignatureInvalid))
    }
