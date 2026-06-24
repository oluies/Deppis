package engine

/** The seam between the client engine and the PONG store + PING notify backend (T032a).
  *
  * Cross-platform by design: the engine ([[Engine]]) depends only on this interface, so the same
  * code drives a real backend on the JVM (gRPC to the oblivious sidecar) and would drive a
  * gRPC-web backend in the browser. The engine derives all tokens and frames; the transport only
  * moves opaque bytes — it never sees plaintext, keys, or which buddy a token belongs to.
  *
  * All three operations are oblivious from the transport's view: `submit`/`retrieve` are keyed by a
  * retrieval token (the store reveals nothing about sender/receiver), and `mailWaiting` returns only
  * "did some buddy write this round" for this client's aggregation label — never which buddy. */
trait RoundTransport:

  /** Store a framed message under its retrieval token (PONG store write). Returns `true` iff the
    * frame was accepted by the backend; on `false` the engine keeps the frame queued and retries it
    * next round (so a transient backend failure never silently drops a message). */
  def submit(token: Array[Byte], frame: Array[Byte]): Boolean

  /** This round's PING notify digest for `clientLabel` (one fetch per round). Each of the client's
    * buddies maps to a one-hot bit; a set bit means THAT buddy signaled mail this round, so the
    * engine reads exactly the signaled buddy (always a hit ⇒ a non-recurrent read token, FR-014) and
    * emits `notified` first (FR-004). An all-zero digest (carrier) ⇒ no mail. */
  def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte]

  /** Retrieve (and consume) a framed message under a token, if one is present (PONG store read,
    * single-use). `None` means no message under that token this round. */
  def retrieve(token: Array[Byte]): Option[Array[Byte]]

  /** The privacy status of THIS backend (T058, Constitution IV/IX). The engine surfaces it as the
    * client's privacy label, so the UI reports `METADATA PRIVATE` ONLY when connected to a real
    * backend whose attestation passed. Defaults to the dev status: a transport must explicitly
    * declare itself private (only the attested enclave-target front does), so a label can never be
    * accidentally promoted. */
  def privacyStatus: privacy.Privacy.BuildPrivacyStatus =
    privacy.Privacy.BuildPrivacyStatus(privacy.Privacy.Backend.Dev, attestationPassed = false)
