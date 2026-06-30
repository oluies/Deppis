package transport

import metadatamessenger.attestation.v1.attestation.*
import attestation.{AttestationResult, Dcap, Measurement, Quote, ReferenceValues}
import com.google.protobuf.ByteString
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.{ManagedChannel, Server}
import java.security.{KeyPair, KeyPairGenerator, SecureRandom, Signature}
import java.security.spec.ECGenParameterSpec
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import org.scalatest.funsuite.AnyFunSuite

/** T056: the attestation relying-party gRPC front. The enclave serves `Attest(client_nonce)` with
  * **evidence** (a DCAP quote binding the nonce + measurement + enclave key); the CLIENT re-appraises
  * that evidence under its OWN pinned policy (the attestation key it trusts + reference values) and
  * accepts the enclave key ONLY on a passing, hardware-backed result (Constitution IX). Exercised
  * over a real in-process gRPC channel with a synthetic (software-signed) quote — no SGX hardware. */
class AttestationServiceSpec extends AnyFunSuite:

  private def bytes(xs: Int*): Vector[Byte] = xs.map(_.toByte).toVector
  private val mrEnclave = bytes(1, 2, 3, 4)
  private val mrSigner = bytes(9, 9, 9)
  private val measurement = Measurement(mrEnclave, mrSigner)
  private val refs = ReferenceValues(Set(measurement))
  private val enclaveKey = Array[Byte](0x42, 0x43, 0x44)

  private def ecKeyPair(): KeyPair =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom())
    kpg.generateKeyPair()

  /** Run `body` against a fresh in-process gRPC server hosting `impl`. */
  private def withClient(impl: AttestationServiceGrpc.AttestationService)(
      body: AttestationServiceGrpc.AttestationServiceBlockingStub => Unit
  ): Unit =
    val name = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder
        .forName(name)
        .directExecutor()
        .addService(AttestationServiceGrpc.bindService(impl, global))
        .build()
        .start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try body(AttestationServiceGrpc.blockingStub(channel))
    finally
      channel.shutdownNow()
      server.shutdownNow()

  test("passing: client pins the platform key + measurement ⇒ provisions the attested enclave key"):
    val kp = ecKeyPair()
    val impl =
      new AttestationServiceImpl(measurement, enclaveKey, kp.getPrivate, Seq(measurement))
    withClient(impl) { stub =>
      val client =
        new AttestationProvisioningClient(stub, kp.getPublic.getEncoded, refs)
      val out = client.provision()
      val enclave = out.toOption.get
      assert(enclave.enclavePublicKey == enclaveKey.toVector)
      assert(enclave.attested) // DcapAttestationVerifier is hardware-backed ⇒ attested
    }

  test("wrong pinned attestation key ⇒ signature invalid, NO key released"):
    val kp = ecKeyPair()
    val impl =
      new AttestationServiceImpl(measurement, enclaveKey, kp.getPrivate, Seq(measurement))
    withClient(impl) { stub =>
      val (otherPub, _) = (ecKeyPair().getPublic.getEncoded, ()) // unrelated key
      val client = new AttestationProvisioningClient(stub, otherPub, refs)
      assert(client.provision() == Left(AttestationResult.SignatureInvalid))
    }

  test("measurement not in the pinned reference set ⇒ untrusted, NO key released"):
    val kp = ecKeyPair()
    val impl =
      new AttestationServiceImpl(measurement, enclaveKey, kp.getPrivate, Seq(measurement))
    withClient(impl) { stub =>
      val foreignRefs = ReferenceValues(Set(Measurement(bytes(7, 7, 7), bytes(8, 8))))
      val client = new AttestationProvisioningClient(stub, kp.getPublic.getEncoded, foreignRefs)
      assert(client.provision() == Left(AttestationResult.MeasurementUntrusted))
    }

  test("anti-replay: evidence bound to a DIFFERENT nonce than minted ⇒ NonceMismatch, NO key"):
    // A server that echoes the client's nonce (defeating the cheap echo check) but signs a quote that
    // BINDS a stale/foreign nonce. The replay must still be caught — by the appraisal's constant-time
    // nonce-binding check over the signed evidence — not by the echo. Proves the guarantee end-to-end.
    val kp = ecKeyPair()
    val foreignNonce = (0 until 16).map(_ => 0x11.toByte).toVector
    val replayImpl = new AttestationServiceGrpc.AttestationService:
      def attest(req: AttestRequest): Future[AttestResponse] =
        val unsigned =
          Quote(measurement, enclaveKey.toVector, foreignNonce, signature = Vector.empty)
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(kp.getPrivate); sig.update(Dcap.quoteBody(unsigned))
        val q = unsigned.copy(signature = sig.sign.toVector)
        Future.successful(
          AttestResponse(
            evidence = ByteString.copyFrom(Dcap.serializeQuote(q)),
            echoedNonce = req.clientNonce, // echo matches ⇒ mismatch must be caught by the binding
            enclavePublicKey = ByteString.copyFrom(enclaveKey)
          )
        )
    withClient(replayImpl) { stub =>
      val client = new AttestationProvisioningClient(stub, kp.getPublic.getEncoded, refs)
      assert(client.provision() == Left(AttestationResult.NonceMismatch))
    }

  test("each provision mints a fresh nonce that the evidence binds (freshness, no replay)"):
    // Two provisions over the same enclave must each bind a DIFFERENT nonce into the quote — proving
    // the result is bound to the client's challenge, not a replayable static quote.
    val kp = ecKeyPair()
    val seen = scala.collection.mutable.Set.empty[Vector[Byte]]
    val inner = new AttestationServiceImpl(measurement, enclaveKey, kp.getPrivate, Seq(measurement))
    val recordingImpl = new AttestationServiceGrpc.AttestationService:
      def attest(req: AttestRequest) =
        seen += req.clientNonce.toByteArray.toVector
        inner.attest(req)
    withClient(recordingImpl) { stub =>
      val client = new AttestationProvisioningClient(stub, kp.getPublic.getEncoded, refs)
      assert(client.provision().isRight)
      assert(client.provision().isRight)
    }
    assert(seen.size == 2, "two provisions must mint two distinct nonces")
