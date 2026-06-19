package transport

import metadatamessenger.store.v1.{store as spb}
import store.ObliviousStore
import frame.Frame
import com.google.protobuf.ByteString
import scala.concurrent.{ExecutionContext, Future}

/** gRPC sidecar-shim `ObliviousStore` service (contract `store.proto`). This is the service the
  * real Rust oblivious sidecar serves inside the enclave; here it is backed by a Scala
  * `ObliviousStore` (e.g. the dev store) so the enclave-target client front can be tested over the
  * same contract. `readBatch` always returns a fixed-size `sealed_result` (carrier on miss), so
  * hit-vs-miss is not observable. */
final class StoreServiceImpl(store: ObliviousStore)(using ec: ExecutionContext)
    extends spb.ObliviousStoreGrpc.ObliviousStore:

  def writeBatch(req: spb.WriteBatchRequest): Future[spb.WriteBatchResponse] = Future {
    req.entries.foreach(e => store.write(e.writeToken.toByteArray, e.frame.toByteArray): Unit)
    spb.WriteBatchResponse(roundId = req.roundId)
  }

  def readBatch(req: spb.ReadBatchRequest): Future[spb.ReadBatchResponse] = Future {
    val results = req.entries.map { e =>
      val sealedBytes = store.read(e.retrievalToken.toByteArray).toOption.flatten.getOrElse(Frame.carrier())
      spb.ReadResult(sealedResult = ByteString.copyFrom(sealedBytes))
    }
    spb.ReadBatchResponse(roundId = req.roundId, results = results)
  }
