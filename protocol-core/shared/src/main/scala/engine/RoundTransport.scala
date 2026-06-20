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

  /** Store a framed message under its retrieval token (PONG store write). */
  def submit(token: Array[Byte], frame: Array[Byte]): Unit

  /** Does this round have mail for this client? (PING notify digest for `clientLabel` — true iff
    * some bit is set.) Polled BEFORE retrieval, so the engine can emit `notified` first (FR-004). */
  def mailWaiting(roundId: Long, clientLabel: Array[Byte]): Boolean

  /** Retrieve (and consume) a framed message under a token, if one is present (PONG store read,
    * single-use). `None` means no message under that token this round. */
  def retrieve(token: Array[Byte]): Option[Array[Byte]]
