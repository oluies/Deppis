package transport

import metadatamessenger.notify.v1.notify.*
import ping.DevNotificationServer
import crypto.Crypto
import notify.Notification
import com.google.protobuf.ByteString
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.{ManagedChannel, Server}
import scala.concurrent.ExecutionContext.Implicits.global
import org.scalatest.funsuite.AnyFunSuite

/** In-process gRPC CONTRACT test for the `NotificationService` wire shape (T028).
  *
  * Distinct from `NotificationServiceSpec` (which exercises the dev backend's behaviour): this
  * spec pins the proto round-trip itself — that `Signal` / `FetchDigest` messages carry the
  * fields the contract promises and that the served `FetchDigestResponse.digest` is always a
  * fixed-size, public bit-vector. No Rust `obsd` is involved; the service is bound over an
  * in-process channel so only the wire contract (message shapes + status) is under test. */
class NotifyContractSpec extends AnyFunSuite:

  private def bs(b: Array[Byte]): ByteString = ByteString.copyFrom(b)

  /** Reconstruct a `Digest` view from the wire bytes so set bits can be read back. */
  private def digestOf(b: ByteString): Notification.Digest =
    var d = Notification.Digest.empty
    val bytes = b.toByteArray
    (0 until bytes.length * 8).foreach(i =>
      if (bytes(i >> 3) & (1 << (i & 7))) != 0 then d = d.set(i)
    )
    d

  private def withClient(ns: DevNotificationServer)(
      body: NotificationServiceGrpc.NotificationServiceBlockingStub => Unit
  ): Unit =
    val name = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder
        .forName(name)
        .directExecutor()
        .addService(NotificationServiceGrpc.bindService(new NotificationServiceImpl(ns), global))
        .build()
        .start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try body(NotificationServiceGrpc.blockingStub(channel))
    finally
      channel.shutdownNow()
      server.shutdownNow()

  private val key = Array.tabulate(Crypto.KeyBytes)(_.toByte)
  private val label = "bob".getBytes

  test("FetchDigest on an empty round returns a fixed-size all-zero carrier digest"):
    val ns = DevNotificationServer(key)
    withClient(ns) { client =>
      val resp = client.fetchDigest(FetchDigestRequest(roundId = 7L, clientLabel = bs(label)))
      // The contract echoes the requested round and serves a public, fixed-width bit-vector.
      assert(resp.roundId == 7L)
      assert(resp.digest.size == Notification.DigestBytes)
      assert(digestOf(resp.digest).isEmpty)
    }

  test("Signal a sealed token, then FetchDigest carries exactly that one bit on the wire"):
    val ns = DevNotificationServer(key)
    withClient(ns) { client =>
      val sealedToken = ns.issueToken(3L, 11, label)
      val sigResp = client.signal(SignalRequest(roundId = 3L, sealedToken = bs(sealedToken)))
      assert(sigResp.roundId == 3L) // SignalResponse echoes the round, no payload leaked
      val resp = client.fetchDigest(FetchDigestRequest(roundId = 3L, clientLabel = bs(label)))
      assert(resp.roundId == 3L)
      assert(resp.digest.size == Notification.DigestBytes)
      val d = digestOf(resp.digest)
      assert(d.get(11) && d.popcount == 1)
    }

  test("a forged Signal token is rejected uniformly and the service stays serving"):
    val ns = DevNotificationServer(key)
    withClient(ns) { client =>
      // Forged blob: well-formed length but no valid AEAD tag for the server key.
      val forged = Array.fill[Byte](Crypto.NonceBytes + 16)(0)
      val resp = client.signal(SignalRequest(roundId = 4L, sealedToken = bs(forged)))
      assert(resp.roundId == 4L) // uniform SignalResponse, no error surfaced (Constitution II)
      // No bit set, and the channel is still usable for a subsequent legitimate round-trip.
      assert(
        digestOf(
          client.fetchDigest(FetchDigestRequest(roundId = 4L, clientLabel = bs(label))).digest
        ).isEmpty
      )
      val good = ns.issueToken(4L, 2, label)
      client.signal(SignalRequest(roundId = 4L, sealedToken = bs(good)))
      val after = digestOf(
        client.fetchDigest(FetchDigestRequest(roundId = 4L, clientLabel = bs(label))).digest
      )
      assert(after.get(2) && after.popcount == 1)
    }
