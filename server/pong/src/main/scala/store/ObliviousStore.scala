package store

/** ObliviousStore (PONG role) interface (T016, Constitution VIII). A dev implementation (plain
  * key-value, NO access-pattern privacy) and a target implementation (enclave oblivious hash
  * table) both satisfy this; the active one is chosen by config.
  *
  * INVARIANTS the target impl must uphold (and which the dev impl explicitly does NOT, hence
  * its label): access pattern depends only on public batch size; writes are unlinkable from
  * reads; `retrievalToken` is non-recurrent (single-use, FR-014). `metadataPrivate` drives the
  * labeling rule (Constitution IV). */
trait ObliviousStore:
  /** Store one fixed-size (256-byte) frame under a write token. */
  def write(writeToken: Array[Byte], frame: Array[Byte]): Either[String, Unit]

  /** Single-use read by retrieval token. Returns the frame once; a second read of the same
    * token MUST return None (non-recurrence). */
  def read(retrievalToken: Array[Byte]): Either[String, Option[Array[Byte]]]

  /** False for dev/stub backends (Constitution IV). */
  def metadataPrivate: Boolean
