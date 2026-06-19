package transport

import metadatamessenger.notify.v1.{notify as npb}
import privacy.Privacy
import com.google.protobuf.ByteString
import scala.util.control.NonFatal

/** Enclave-target notification front (T054, Constitution VIII): the Scala server's client to the
  * PING `NotificationService` — in real deployment the Rust oblivious-aggregation sidecar running
  * inside the SGX enclave.
  *
  * `metadataPrivate` is true ONLY when the enclave's attestation has passed (Constitution IV/IX);
  * an unattested enclave-target backend is NOT private and is labeled accordingly. gRPC failures
  * map to the `Left` channel (generic message, no secret-dependent content — Constitution II). */
final class EnclaveNotificationClient(
    stub: npb.NotificationServiceGrpc.NotificationServiceBlockingStub,
    attested: Boolean
):
  def metadataPrivate: Boolean = attested
  def label: String            = if attested then "METADATA PRIVATE" else Privacy.DevLabel

  /** Submit a receiver-sealed token for a round; always succeeds uniformly server-side. */
  def signal(roundId: Long, sealedToken: Array[Byte]): Either[String, Unit] =
    try
      stub.signal(npb.SignalRequest(roundId = roundId, sealedToken = ByteString.copyFrom(sealedToken)))
      Right(())
    catch case NonFatal(_) => Left("notification signal failed")

  /** Fetch (and consume) this round's digest bytes for a client label; carrier all-zero when no
    * mail waits, so the response reveals only that some buddy wrote, never which. */
  def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Either[String, Array[Byte]] =
    try
      val resp = stub.fetchDigest(npb.FetchDigestRequest(roundId = roundId, clientLabel = ByteString.copyFrom(clientLabel)))
      Right(resp.digest.toByteArray)
    catch case NonFatal(_) => Left("notification fetch failed")
