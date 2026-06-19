package transport

import metadatamessenger.store.v1.{store as spb}
import store.ObliviousStore
import privacy.Privacy
import com.google.protobuf.ByteString

/** Enclave-target `ObliviousStore` front (T054, Constitution VIII): implements the `ObliviousStore`
  * interface by calling the `ObliviousStore` gRPC service — in real deployment the Rust oblivious
  * sidecar running inside the SGX enclave.
  *
  * `metadataPrivate` is true ONLY when the enclave's attestation has passed (Constitution IV/IX);
  * an enclave-target backend whose attestation has not been verified is NOT private and is labeled
  * accordingly. */
final class EnclaveObliviousStore(
    stub: spb.ObliviousStoreGrpc.ObliviousStoreBlockingStub,
    attested: Boolean
) extends ObliviousStore:

  def metadataPrivate: Boolean = attested
  def label: String            = if attested then "METADATA PRIVATE" else Privacy.DevLabel

  def write(writeToken: Array[Byte], frame: Array[Byte]): Either[String, Unit] =
    stub.writeBatch(
      spb.WriteBatchRequest(
        roundId = 0L,
        batchSize = 1,
        entries = Seq(spb.WriteEntry(writeToken = ByteString.copyFrom(writeToken), frame = ByteString.copyFrom(frame)))
      )
    )
    Right(())

  def read(retrievalToken: Array[Byte]): Either[String, Option[Array[Byte]]] =
    val resp = stub.readBatch(
      spb.ReadBatchRequest(
        roundId = 0L,
        batchSize = 1,
        entries = Seq(spb.ReadEntry(retrievalToken = ByteString.copyFrom(retrievalToken)))
      )
    )
    val sealedBytes = resp.results.head.sealedResult.toByteArray
    // carrier (all-zero) => miss; any content => hit. An empty-payload frame is indistinguishable
    // from a miss at this bridge, but real frames carry a non-zero length prefix.
    Right(if sealedBytes.forall(_ == 0) then None else Some(sealedBytes))
