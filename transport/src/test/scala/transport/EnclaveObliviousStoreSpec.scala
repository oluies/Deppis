package transport

import metadatamessenger.store.v1.{store as spb}
import store.dev.DevObliviousStore
import frame.Frame
import privacy.Privacy
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.{ManagedChannel, Server}
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import org.scalatest.funsuite.AnyFunSuite

class EnclaveObliviousStoreSpec extends AnyFunSuite:

  private def frame(b: Byte): Array[Byte] = Frame.pad(Array(b)).toOption.get

  /** Stand up a StoreService backed by a fresh dev store and hand the test an enclave-target front
    * speaking to it over in-process gRPC. */
  private def withEnclave(attested: Boolean)(body: EnclaveObliviousStore => Unit): Unit =
    val dev  = new DevObliviousStore()
    val name = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder.forName(name).directExecutor()
        .addService(spb.ObliviousStoreGrpc.bindService(new StoreServiceImpl(dev), global))
        .build().start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try body(new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested))
    finally
      channel.shutdownNow()
      server.shutdownNow()

  test("enclave-target front is private only when attested (Constitution IV/IX)"):
    withEnclave(attested = false) { e =>
      assert(!e.metadataPrivate)
      assert(e.label == Privacy.DevLabel)
    }
    withEnclave(attested = true)(e => assert(e.metadataPrivate))

  test("write then read over gRPC returns the frame; token is single-use"):
    withEnclave(attested = true) { e =>
      val tok = "tok-1".getBytes
      val fr  = frame(7)
      assert(e.write(tok, fr).isRight)
      assert(e.read(tok).toOption.flatten.exists(_.sameElements(fr))) // hit
      assert(e.read(tok).toOption.flatten.isEmpty)                    // single-use -> miss
    }

  test("a miss returns None (carrier)"):
    withEnclave(attested = true)(e => assert(e.read("nope".getBytes).toOption.flatten.isEmpty))

  test("an empty-payload frame round-trips as a hit (found tag, not content)"):
    withEnclave(attested = true) { e =>
      val tok   = "empty".getBytes
      val empty = Frame.carrier() // valid empty-payload frame — byte-identical to a carrier
      assert(e.write(tok, empty).isRight)
      // must be Some(empty), NOT None: the found tag distinguishes a stored empty frame from a miss
      assert(e.read(tok).toOption.flatten.exists(_.sameElements(empty)))
    }

  test("unattested front serves data on a real path but surfaces the DEV label"):
    withEnclave(attested = false) { e =>
      assert(!e.metadataPrivate && e.label == Privacy.DevLabel)
      val tok = "t".getBytes
      assert(e.write(tok, frame(3)).isRight)
      assert(e.read(tok).toOption.flatten.exists(_.sameElements(frame(3))))
    }

  test("a transport failure maps to Left (error channel)"):
    val name = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder.forName(name).directExecutor()
        .addService(spb.ObliviousStoreGrpc.bindService(new StoreServiceImpl(new DevObliviousStore()), global))
        .build().start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    val e = new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested = true)
    channel.shutdownNow() // kill the transport before the RPC
    server.shutdownNow()
    assert(e.read("x".getBytes).isLeft)
    assert(e.write("x".getBytes, frame(1)).isLeft)

  test("an empty results response maps to Left (malformed-response guard)"):
    val emptyService = new spb.ObliviousStoreGrpc.ObliviousStore:
      def writeBatch(req: spb.WriteBatchRequest): Future[spb.WriteBatchResponse] =
        Future.successful(spb.WriteBatchResponse(req.roundId))
      def readBatch(req: spb.ReadBatchRequest): Future[spb.ReadBatchResponse] =
        Future.successful(spb.ReadBatchResponse(req.roundId, Seq.empty)) // contract violation
    val name = InProcessServerBuilder.generateName()
    val server: Server =
      InProcessServerBuilder.forName(name).directExecutor()
        .addService(spb.ObliviousStoreGrpc.bindService(emptyService, global)).build().start()
    val channel: ManagedChannel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try
      val e = new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested = true)
      assert(e.read("x".getBytes) == Left("empty store response"))
    finally
      channel.shutdownNow()
      server.shutdownNow()
