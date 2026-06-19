package transport

import metadatamessenger.notify.v1.{notify as npb}
import ping.DevNotificationServer
import crypto.Crypto
import privacy.Privacy
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.{ManagedChannel, Server}
import scala.concurrent.ExecutionContext.Implicits.global
import org.scalatest.funsuite.AnyFunSuite

class EnclaveNotificationClientSpec extends AnyFunSuite:

  private val key   = Array.tabulate(Crypto.KeyBytes)(_.toByte)
  private val label = "alice".getBytes

  private def bit(digest: Array[Byte], b: Int): Boolean = (digest(b >> 3) & (1 << (b & 7))) != 0

  /** Run `body` with an enclave-target notification front speaking in-process to a
    * NotificationService backed by a fresh DevNotificationServer (also handed to the body so a
    * receiver can issue sealed tokens). */
  private def withClient(attested: Boolean)(body: (EnclaveNotificationClient, DevNotificationServer) => Unit): Unit =
    val ns   = DevNotificationServer(key)
    val name = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder.forName(name).directExecutor()
        .addService(npb.NotificationServiceGrpc.bindService(new NotificationServiceImpl(ns), global))
        .build().start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try body(new EnclaveNotificationClient(npb.NotificationServiceGrpc.blockingStub(channel), attested), ns)
    finally
      channel.shutdownNow()
      server.shutdownNow()

  test("front is private only when attested (Constitution IV/IX)"):
    withClient(attested = false)((c, _) => assert(!c.metadataPrivate && c.label == Privacy.DevLabel))
    withClient(attested = true)((c, _) => assert(c.metadataPrivate))

  test("signal then fetchDigest reports the buddy's bit over gRPC; fetch consumes it"):
    withClient(attested = true) { (client, ns) =>
      assert(client.signal(1L, ns.issueToken(5, label)).isRight)
      val d = client.fetchDigest(1L, label).toOption.get
      assert(bit(d, 5))
      assert(client.fetchDigest(1L, label).toOption.get.forall(_ == 0)) // consumed -> carrier
    }

  test("a forged token still yields a uniform success but sets no bit (FR-003)"):
    withClient(attested = true) { (client, _) =>
      assert(client.signal(2L, Array.fill[Byte](40)(0)).isRight) // uniform, no error leaked
      assert(client.fetchDigest(2L, label).toOption.get.forall(_ == 0))
    }

  test("a transport failure maps to Left (error channel)"):
    val ns   = DevNotificationServer(key)
    val name = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder.forName(name).directExecutor()
        .addService(npb.NotificationServiceGrpc.bindService(new NotificationServiceImpl(ns), global))
        .build().start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    val c = new EnclaveNotificationClient(npb.NotificationServiceGrpc.blockingStub(channel), attested = true)
    channel.shutdownNow()
    server.shutdownNow()
    assert(c.signal(1L, "x".getBytes).isLeft)
    assert(c.fetchDigest(1L, label).isLeft)
