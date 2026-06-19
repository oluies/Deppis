package transport

import metadatamessenger.messaging.v1.messaging.*
import store.dev.DevObliviousStore
import frame.Frame
import token.RetrievalToken
import com.google.protobuf.ByteString
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.{ManagedChannel, Server}
import scala.concurrent.ExecutionContext.Implicits.global
import org.scalatest.funsuite.AnyFunSuite

class RoundServiceSpec extends AnyFunSuite:

  private def bs(b: Array[Byte]): ByteString = ByteString.copyFrom(b)

  test("send then retrieve over in-process gRPC: hit returns the frame, miss returns a carrier, token is single-use"):
    val store      = new DevObliviousStore()
    val name       = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder.forName(name).directExecutor()
        .addService(RoundServiceGrpc.bindService(new RoundServiceImpl(store), global))
        .build().start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try
      val client = RoundServiceGrpc.blockingStub(channel)
      val tok    = RetrievalToken.derive("k".getBytes, "A", "B", 1L)
      val fr     = Frame.pad("hi".getBytes).toOption.get

      client.sendFrame(SendFrameRequest(roundId = 1L, writeToken = bs(tok), frame = bs(fr), isCarrier = false))

      val resp = client.retrieve(RetrieveRequest(roundId = 1L, retrievalTokens = Seq(bs(tok), bs("missing".getBytes))))
      assert(resp.sealedFrames.size == 2)
      assert(resp.sealedFrames(0).toByteArray.sameElements(fr))             // hit
      assert(resp.sealedFrames(1).toByteArray.sameElements(Frame.carrier())) // miss -> carrier

      // single-use: a second retrieve of the same token now misses -> carrier (FR-014)
      val resp2 = client.retrieve(RetrieveRequest(roundId = 1L, retrievalTokens = Seq(bs(tok))))
      assert(resp2.sealedFrames(0).toByteArray.sameElements(Frame.carrier()))
    finally
      channel.shutdownNow()
      server.shutdownNow()

  test("a carrier sendFrame stores nothing (uniform shape, no real write)"):
    val store = new DevObliviousStore()
    val name  = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder.forName(name).directExecutor()
        .addService(RoundServiceGrpc.bindService(new RoundServiceImpl(store), global))
        .build().start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try
      val client = RoundServiceGrpc.blockingStub(channel)
      client.sendFrame(SendFrameRequest(roundId = 2L, writeToken = ByteString.EMPTY, frame = bs(Frame.carrier()), isCarrier = true))
      val resp = client.retrieve(RetrieveRequest(roundId = 2L, retrievalTokens = Seq(bs("anything".getBytes))))
      assert(resp.sealedFrames(0).toByteArray.sameElements(Frame.carrier()))
    finally
      channel.shutdownNow()
      server.shutdownNow()
