package transport

import engine.RoundTransport

/** JVM [[engine.RoundTransport]] backed by the real PONG store + PING notify fronts (T032a).
  *
  * This is the adapter that lets the cross-platform client engine drive the actual oblivious
  * sidecar over gRPC: `submit`/`retrieve` go to the [[EnclaveObliviousStore]] and `mailWaiting`
  * polls the [[EnclaveNotificationClient]] digest. The engine derives every token; this layer only
  * moves opaque bytes, so it learns nothing about sender/receiver or plaintext.
  *
  * Operations are best-effort at the round boundary: a transient backend failure (mapped to `Left`
  * by the fronts, with a fixed non-secret message — Constitution II) does not throw out of `tick`;
  * the message simply isn't delivered this round and is retried next round (the token is unchanged
  * until a successful retrieval advances the counter). */
final class GrpcRoundTransport(
    store: EnclaveObliviousStore,
    notify: EnclaveNotificationClient
) extends RoundTransport:

  def submit(token: Array[Byte], frame: Array[Byte]): Unit =
    store.write(token, frame) // best-effort; Left is swallowed (retried next round)
    ()

  /** Mail waits iff this client's notify digest has any bit set this round. */
  def mailWaiting(roundId: Long, clientLabel: Array[Byte]): Boolean =
    notify.fetchDigest(roundId, clientLabel).toOption.exists(d => d.exists(_ != 0))

  def retrieve(token: Array[Byte]): Option[Array[Byte]] =
    store.read(token).toOption.flatten
