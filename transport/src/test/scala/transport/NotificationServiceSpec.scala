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

class NotificationServiceSpec extends AnyFunSuite:

  private def bs(b: Array[Byte]): ByteString = ByteString.copyFrom(b)
  private def digestOf(b: ByteString): Notification.Digest =
    // reconstruct a Digest view to read bits (server returned raw digest bytes)
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
  private val label = "alice".getBytes

  test("signal then fetchDigest over gRPC reports the buddy's bit; fetch consumes it"):
    val ns = DevNotificationServer(key)
    withClient(ns) { client =>
      client.signal(SignalRequest(roundId = 1L, sealedToken = bs(ns.issueToken(1L, 5, label))))
      val d1 = digestOf(
        client.fetchDigest(FetchDigestRequest(roundId = 1L, clientLabel = bs(label))).digest
      )
      assert(d1.get(5) && d1.popcount == 1)
      // consumed: a second fetch is an all-zero carrier
      val d2 = digestOf(
        client.fetchDigest(FetchDigestRequest(roundId = 1L, clientLabel = bs(label))).digest
      )
      assert(d2.isEmpty)
    }

  test("a forged token yields a uniform SignalResponse but never sets a bit (FR-003)"):
    val ns = DevNotificationServer(key)
    withClient(ns) { client =>
      val resp =
        client.signal(SignalRequest(roundId = 2L, sealedToken = bs(Array.fill[Byte](40)(0))))
      assert(resp.roundId == 2L) // uniform response, no error leaked
      val d = digestOf(
        client.fetchDigest(FetchDigestRequest(roundId = 2L, clientLabel = bs(label))).digest
      )
      assert(d.isEmpty)
    }
