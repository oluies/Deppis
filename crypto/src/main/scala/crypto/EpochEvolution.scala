package crypto

/** Verifiable per-epoch key evolution for US7 (forward secrecy across epochs), built on the 2HashDH
  * [[Voprf]].
  *
  * ==Goal (US7)==
  *   (a) '''Forward secrecy across epochs''': a party holding epoch `e`'s key cannot derive the key
  *       of any PAST epoch `e' < e`.
  *   (b) '''Verifiable evolution''': the client can check the server evolved the key correctly
  *       against the server's PUBLIC key commitment (public transcript). A malicious server that
  *       substitutes keys or partitions users fails verification.
  *
  * ==Construction==
  * For a client identified by a stable, per-client `clientContext` (opaque bytes — e.g. a hashed
  * account/channel id) and epoch index `e`, the epoch key is
  * {{{ epochKey(e) = KDF( VOPRF(k, "epoch" ‖ e ‖ clientContext), info = "epoch-key" ‖ e ) }}}
  * The VOPRF is run '''obliviously''': the server never sees `clientContext` or `e` (only a blinded
  * group element), so it cannot link a client across epochs by the input value, yet it '''proves'''
  * (DLEQ) that it used the key committed in its published `pk`.
  *
  * ==Why (a) holds — forward secrecy across epochs==
  * Each epoch's input embeds a DISTINCT epoch index, so `VOPRF(k, ·)` yields '''independent,
  * pseudorandom''' outputs per epoch (VOPRF is a PRF). The per-epoch key is a one-way KDF of that
  * output. Therefore epoch `e`'s key carries no information about epoch `e'`'s output or key: given
  * `epochKey(e)` you cannot compute `epochKey(e')` for `e' ≠ e`. (This is forward secrecy *of the
  * evolved epoch keys*: compromising one derived epoch key does not expose neighbours. Compromising
  * the SERVER's long-term OPRF key `k` lets the holder recompute any epoch's output — that key is
  * the server's root secret and is out of scope for per-epoch FS, exactly like a KDF root; the
  * ratchet, unchanged here, provides the message-level PCS.)
  *
  * ==Why (b) holds — verifiable==
  * [[Voprf.finalizeEval]] verifies the server's DLEQ proof against `serverPublicKey` BEFORE
  * unblinding; a wrong key or tampered proof/evaluation is rejected (`Left`) and NO key is derived.
  *
  * ==Constitution I==
  * Composes only vetted primitives: the [[Voprf]] group protocol (itself libsodium ristretto255 +
  * SHA-512) and [[Crypto.kdf]] (keyed Blake2b). Nothing is hand-rolled here.
  *
  * This wraps the epoch-key derivation; it does NOT touch the message ratchet. */
object EpochEvolution:

  /** Derived per-epoch key length in bytes (fits a symmetric key). */
  val EpochKeyBytes: Int = 32

  private def epochLabel(epoch: Long): Array[Byte] =
    val b = new Array[Byte](8)
    var v = epoch
    var i = 7
    while i >= 0 do
      b(i) = (v & 0xff).toByte
      v >>>= 8
      i -= 1
    b

  /** The oblivious VOPRF input for `(clientContext, epoch)`: length-prefixed (shared framing) so
    * different `(context, epoch)` pairs never collide. */
  private def epochInput(clientContext: Array[Byte], epoch: Long): Array[Byte] =
    Encoding.lengthPrefixed("epoch".getBytes("UTF-8"), epochLabel(epoch), clientContext)

  /** Client state for one evolution round, to be paired with the server's [[Voprf.Evaluation]]. */
  final case class EvolveRequest(
      epoch: Long,
      state: Voprf.BlindState,
      blinded: Voprf.BlindedElement
  )

  /** Server key pair for epoch evolution: the OPRF key + its published commitment. Re-exported so
    * callers derive/verify against exactly this `publicKey`. */
  export Voprf.ServerKeyPair
  export Voprf.Evaluation
  export Voprf.BlindedElement

  /** Generate the server's epoch-evolution key (OPRF key + public commitment `pk = k·B`). */
  def serverKeygen(): Voprf.ServerKeyPair = Voprf.keygen()

  /** '''Client, step 1''': blind the epoch input for `(clientContext, epoch)`. Send
    * `request.blinded` to the server; keep `request` for step 3. */
  def beginEvolve(clientContext: Array[Byte], epoch: Long): EvolveRequest =
    val (st, be) = Voprf.blind(epochInput(clientContext, epoch))
    EvolveRequest(epoch, st, be)

  /** '''Server, step 2''': evaluate the blinded element under the OPRF key and attach a DLEQ proof.
    * The server learns neither `clientContext` nor `epoch`. */
  def serverEvolve(secretKey: Array[Byte], blinded: Voprf.BlindedElement): Voprf.Evaluation =
    Voprf.evaluate(secretKey, blinded)

  /** '''Client, step 3''': verify the DLEQ proof against `serverPublicKey`, unblind, and derive the
    * epoch key. Returns `Left` (and NO key) if the proof fails — a server that used a different key
    * or tampered with the response is rejected. */
  def completeEvolve(
      serverPublicKey: Array[Byte],
      request: EvolveRequest,
      eval: Voprf.Evaluation
  ): Either[String, Array[Byte]] =
    Voprf
      .finalizeEval(serverPublicKey, request.state, request.blinded, eval)
      .map(prf => deriveEpochKey(prf, request.epoch))

  /** KDF the VOPRF output into the epoch key, binding the epoch index into `info`. */
  private def deriveEpochKey(prfOutput: Array[Byte], epoch: Long): Array[Byte] =
    Crypto.kdf(
      ikm = prfOutput,
      salt = "Deppis-epoch-evolution-v1".getBytes("UTF-8"),
      info = "epoch-key".getBytes("UTF-8") ++ epochLabel(epoch),
      len = EpochKeyBytes
    )
