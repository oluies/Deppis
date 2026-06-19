package transport

import metadatamessenger.store.v1.{store as spb}
import store.ObliviousStore
import frame.Frame
import privacy.Privacy
import com.google.protobuf.ByteString
import scala.util.control.NonFatal

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

  // Derive both from the canonical labeling logic (single source of truth) — no literal drift.
  private val status           = Privacy.BuildPrivacyStatus(Privacy.Backend.EnclaveTarget, attested)
  def metadataPrivate: Boolean = status.metadataPrivate
  def label: String            = status.label

  // gRPC failures surface as exceptions from the blocking stub; map them to the trait's Left
  // channel. Error text is generic (no secret-dependent content, Constitution II).
  def write(writeToken: Array[Byte], frame: Array[Byte]): Either[String, Unit] =
    try
      stub.writeBatch(
        spb.WriteBatchRequest(
          roundId = 0L,
          batchSize = 1,
          entries = Seq(spb.WriteEntry(writeToken = ByteString.copyFrom(writeToken), frame = ByteString.copyFrom(frame)))
        )
      )
      Right(())
    catch case NonFatal(_) => Left("store write failed")

  def read(retrievalToken: Array[Byte]): Either[String, Option[Array[Byte]]] =
    try
      val resp = stub.readBatch(
        spb.ReadBatchRequest(
          roundId = 0L,
          batchSize = 1,
          entries = Seq(spb.ReadEntry(retrievalToken = ByteString.copyFrom(retrievalToken)))
        )
      )
      resp.results.headOption match
        case None => Left("empty store response")
        case Some(r) =>
          val b = r.sealedResult.toByteArray
          // sealed_result = frame (256B) ‖ found tag (1B); the tag carries hit/miss (see contract),
          // so an empty-payload frame is not mistaken for a miss.
          if b.length != Frame.Size + 1 then Left("malformed sealed_result")
          else if b(Frame.Size) == 1.toByte then Right(Some(b.take(Frame.Size)))
          else Right(None)
    catch case NonFatal(_) => Left("store read failed")
