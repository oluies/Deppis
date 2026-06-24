package transport

import engine.RoundTransport

/** JVM [[engine.RoundTransport]] backed by the real PONG store + PING notify fronts (T032a).
  *
  * This is the adapter that lets the cross-platform client engine drive the actual oblivious
  * sidecar over gRPC: `submit`/`retrieve` go to the [[EnclaveObliviousStore]] and `mailWaiting`
  * polls the [[EnclaveNotificationClient]] digest. The engine derives every token; this layer only
  * moves opaque bytes, so it learns nothing about sender/receiver or plaintext.
  *
  * A transient backend failure (mapped to `Left` by the fronts, with a fixed non-secret message —
  * Constitution II) does not throw out of `tick`: `submit` reports `false` so the engine keeps the
  * frame queued for next round, and `retrieve` returns `None` (the receive counter only advances on
  * a consumed frame). So neither a send nor a receive is silently lost on a transient failure. */
final class GrpcRoundTransport(
    store: EnclaveObliviousStore,
    notify: EnclaveNotificationClient
) extends RoundTransport:

  /** `true` iff the store accepted the frame; `false` lets the engine retry next round. */
  def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
    store.write(token, frame).isRight

  /** This round's PING notify digest for the client (per-buddy one-hot bits). On a transient
    * failure, an all-zero digest (no mail) — the message simply waits for next round. */
  def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
    notify.fetchDigest(roundId, clientLabel).toOption.getOrElse(Array.emptyByteArray)

  def retrieve(token: Array[Byte]): Option[Array[Byte]] =
    store.read(token).toOption.flatten

  /** Surface the backend's attestation-gated status so the engine's client label is true (T058): an
    * unattested enclave-target backend stays `DEV, NO METADATA PRIVACY`; only a passing attestation
    * promotes it to `METADATA PRIVATE`. */
  override def privacyStatus: privacy.Privacy.BuildPrivacyStatus = store.privacyStatus
