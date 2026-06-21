package transport.round

import metadatamessenger.messaging.v1.messaging.*
import com.google.protobuf.ByteString
import store.dev.DevObliviousStore
import token.RetrievalToken
import frame.Frame
import io.grpc.{ManagedChannelBuilder, StatusRuntimeException}
import java.util.concurrent.TimeUnit
import scala.concurrent.ExecutionContext.Implicits.global
import org.apache.pekko.actor.testkit.typed.scaladsl.ActorTestKit
import org.scalatest.funsuite.AnyFunSuite

/** Networked TLS-1.3 round-trip for the gRPC `RoundService` (T020) plus the `RoundOrchestrator`
  * round clock. Distinct from the in-process service tests: this exercises a real port and a real
  * TLS handshake with a (dev) self-signed cert. */
class TlsRoundServerSpec extends AnyFunSuite:

  private val key = "round-key".getBytes

  test("RoundService round-trips a frame over a real TLS 1.3 connection"):
    val store = new DevObliviousStore
    val server = TlsRoundServer.bind(store)
    val channel = server.trustingChannel()
    try
      val stub = RoundServiceGrpc.blockingStub(channel)
      val token = RetrievalToken.derive(key, "a", "b", 0L)
      val frame = Frame.pad("hello over tls".getBytes).toOption.get
      stub.sendFrame(
        SendFrameRequest(
          roundId = 1L,
          writeToken = ByteString.copyFrom(token),
          frame = ByteString.copyFrom(frame)
        )
      )
      val resp = stub.retrieve(
        RetrieveRequest(roundId = 1L, retrievalTokens = Seq(ByteString.copyFrom(token)))
      )
      assert(resp.roundId == 1L)
      assert(resp.sealedFrames.size == 1)
      assert(resp.sealedFrames.head.toByteArray.sameElements(frame))
    finally
      channel.shutdownNow()
      server.stop()

  test("a plaintext client cannot talk to the TLS server"):
    val store = new DevObliviousStore
    val server = TlsRoundServer.bind(store)
    val plain = ManagedChannelBuilder.forAddress("localhost", server.port).usePlaintext().build()
    try
      val stub = RoundServiceGrpc.blockingStub(plain).withDeadlineAfter(5, TimeUnit.SECONDS)
      // The TLS server rejects a cleartext HTTP/2 client; the call fails rather than succeeding.
      assertThrows[StatusRuntimeException](stub.sendFrame(SendFrameRequest(roundId = 1L)))
    finally
      plain.shutdownNow()
      server.stop()

  test("RoundOrchestrator advances the round monotonically"):
    val testKit = ActorTestKit()
    try
      val probe = testKit.createTestProbe[Long]()
      val orch = testKit.spawn(RoundOrchestrator())
      orch ! RoundOrchestrator.Current(probe.ref)
      assert(probe.receiveMessage() == 0L)
      orch ! RoundOrchestrator.Advance
      orch ! RoundOrchestrator.Advance
      orch ! RoundOrchestrator.Current(probe.ref)
      assert(probe.receiveMessage() == 2L)
    finally testKit.shutdownTestKit()
