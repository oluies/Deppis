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

  test(
    "send then retrieve over in-process gRPC: hit returns the frame, miss returns a carrier, token is single-use"
  ):
    val store = new DevObliviousStore()
    val name = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder
        .forName(name)
        .directExecutor()
        .addService(RoundServiceGrpc.bindService(new RoundServiceImpl(store), global))
        .build()
        .start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try
      val client = RoundServiceGrpc.blockingStub(channel)
      val tok = RetrievalToken.derive("k".getBytes, "A", "B", 1L)
      val fr = Frame.pad("hi".getBytes).toOption.get

      client.sendFrame(
        SendFrameRequest(roundId = 1L, writeToken = bs(tok), frame = bs(fr), isCarrier = false)
      )

      val resp = client.retrieve(
        RetrieveRequest(roundId = 1L, retrievalTokens = Seq(bs(tok), bs("missing".getBytes)))
      )
      assert(resp.sealedFrames.size == 2)
      assert(resp.sealedFrames(0).toByteArray.sameElements(fr)) // hit
      assert(resp.sealedFrames(1).toByteArray.sameElements(Frame.carrier())) // miss -> carrier

      // single-use: a second retrieve of the same token now misses -> carrier (FR-014)
      val resp2 = client.retrieve(RetrieveRequest(roundId = 1L, retrievalTokens = Seq(bs(tok))))
      assert(resp2.sealedFrames(0).toByteArray.sameElements(Frame.carrier()))
    finally
      channel.shutdownNow()
      server.shutdownNow()

  /** Run `body` against a fresh in-process server over `store`. */
  private def withClient(store: DevObliviousStore)(
      body: RoundServiceGrpc.RoundServiceBlockingStub => Unit
  ): Unit =
    val name = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder
        .forName(name)
        .directExecutor()
        .addService(RoundServiceGrpc.bindService(new RoundServiceImpl(store), global))
        .build()
        .start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try body(RoundServiceGrpc.blockingStub(channel))
    finally
      channel.shutdownNow()
      server.shutdownNow()

  test("a tokenless carrier sendFrame stores nothing (uniform shape, no real write)"):
    withClient(new DevObliviousStore()) { client =>
      client.sendFrame(
        SendFrameRequest(
          roundId = 2L,
          writeToken = ByteString.EMPTY,
          frame = bs(Frame.carrier()),
          isCarrier = true
        )
      )
      val resp = client.retrieve(
        RetrieveRequest(roundId = 2L, retrievalTokens = Seq(bs("anything".getBytes)))
      )
      assert(resp.sealedFrames(0).toByteArray.sameElements(Frame.carrier()))
    }

  test("duplicate write token is ignored: the original frame is preserved"):
    withClient(new DevObliviousStore()) { client =>
      val tok = "dup".getBytes
      val f1 = Frame.pad("first".getBytes).toOption.get
      val f2 = Frame.pad("second".getBytes).toOption.get
      client.sendFrame(
        SendFrameRequest(roundId = 3L, writeToken = bs(tok), frame = bs(f1), isCarrier = false)
      )
      client.sendFrame(
        SendFrameRequest(roundId = 3L, writeToken = bs(tok), frame = bs(f2), isCarrier = false)
      )
      val resp = client.retrieve(RetrieveRequest(roundId = 3L, retrievalTokens = Seq(bs(tok))))
      assert(resp.sealedFrames(0).toByteArray.sameElements(f1)) // original, not clobbered
    }

  test(
    "is_carrier is not trusted: a flagged frame WITH a write token is still written (server blind)"
  ):
    withClient(new DevObliviousStore()) { client =>
      val tok = "tok".getBytes
      val fr = Frame.pad("real".getBytes).toOption.get
      // misleading flag: isCarrier=true but a real token is present -> server writes based on token
      client.sendFrame(
        SendFrameRequest(roundId = 4L, writeToken = bs(tok), frame = bs(fr), isCarrier = true)
      )
      val resp = client.retrieve(RetrieveRequest(roundId = 4L, retrievalTokens = Seq(bs(tok))))
      assert(resp.sealedFrames(0).toByteArray.sameElements(fr))
    }
