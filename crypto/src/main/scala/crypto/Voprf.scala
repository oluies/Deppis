package crypto

/** A **Verifiable Oblivious Pseudorandom Function** (VOPRF), 2HashDH construction over
  * **ristretto255**, following RFC 9497 (OPRF; the *verifiable* "VOPRF" mode with a DLEQ proof).
  *
  * ==What it computes==
  * The server holds a secret key `k`. For a client input `x` the joint function is
  * {{{ F(k, x) = H2( x, k · H1(x) ) }}}
  * where `H1` hashes `x` to a group element and `H2` hashes the transcript to the final PRF output.
  * The client never reveals `x` to the server and the server never reveals `k` to the client:
  *
  *   1. '''Blind''' — client picks a random blind `r`, sends `blinded = r · H1(x)`.
  *   2. '''Evaluate''' — server returns `evaluated = k · blinded` together with a '''DLEQ proof'''
  *      that `log_B(pk) == log_{blinded}(evaluated)` (same `k`), where `pk = k · B` is the server's
  *      PUBLIC key commitment.
  *   3. '''Finalize''' — client '''verifies''' the proof against the server's published `pk`, then
  *      '''unblinds''': `n = r⁻¹ · evaluated = k · H1(x)`, and outputs `H2(x, n)`.
  *
  * ==Why it fits US7 (verifiable epoch-key evolution)==
  *   - '''Oblivious''': the server evolves a client's epoch key without learning the client's input,
  *     so it cannot partition users by input or link epochs by the input value.
  *   - '''Verifiable''': the DLEQ proof binds the evaluation to the server's PUBLIC key. A malicious
  *     server that used a different key (to silently substitute/partition) FAILS verification — the
  *     client rejects instead of accepting a wrong key. This is the "verifiable against a public
  *     transcript" property the task asks for.
  *   - '''Forward secrecy across epochs''': see [[EpochEvolution]] — the input `x` includes the
  *     epoch index, so distinct epochs get independent PRF outputs; the derived per-epoch key is a
  *     KDF of the PRF output and reveals nothing about other epochs' outputs.
  *
  * ==Constitution I — no hand-rolled primitives==
  * Every group/scalar/hash operation is a call into libsodium's vetted ristretto255 + SHA-512
  * ([[Sodium]]). This file only COMPOSES those vetted operations into the RFC 9497 protocol
  * (blinding, the Fiat–Shamir DLEQ transcript, unblinding). No curve, field, or hash is implemented
  * here. Proof comparison is constant-time (`Sodium.memcmp`). On erasure (Constitution II): the
  * NATIVE segments holding secret scalars are zeroed deterministically inside `Sodium` before their
  * arena is freed; the transient secret HEAP arrays that never leave a method (the DLEQ nonce `t`,
  * `c·k`, and the inverse blind `r⁻¹`) are best-effort wiped via `Sodium.wipe` when consumed. Heap
  * arrays that are RETURNED (the OPRF key, the epoch key) are the caller's to manage, and a copying
  * GC can still leave stale copies — so this reduces, not eliminates, the plaintext-secret window.
  *
  * NOTE on domain separation: this is a self-consistent instantiation using fixed context strings,
  * not a byte-for-byte reproduction of RFC 9497's ciphersuite test vectors. It gives the same
  * security properties (obliviousness + verifiability via DLEQ) but is NOT wire-compatible with
  * other RFC 9497 implementations; it is an internal primitive for Deppis epoch evolution. */
object Voprf:

  /** Context label mixed into every hash so outputs are domain-separated from any other use of
    * ristretto255/SHA-512 in the system (and future protocol versions can bump it). */
  private val Context: Array[Byte] = "Deppis-VOPRF-v1-ristretto255-SHA512".getBytes("UTF-8")

  private def tag(label: String): Array[Byte] = label.getBytes("UTF-8")

  /** Length-prefixed concatenation (shared framing — see [[Encoding.lengthPrefixed]]). */
  private def concat(parts: Array[Byte]*): Array[Byte] = Encoding.lengthPrefixed(parts*)

  // ---- H1: hash-to-group, H2: hash-to-scalar (RFC 9497 uses vetted maps; we call libsodium's) ----

  /** `H1(x)` — map input to a ristretto255 group element via SHA-512 → `from_hash`. */
  private def hashToGroup(input: Array[Byte]): Array[Byte] =
    Sodium.r255FromHash(Sodium.sha512(concat(Context, tag("H1"), input)))

  /** Hash to a scalar mod L via SHA-512 → `scalar_reduce` (used for the DLEQ challenge). */
  private def hashToScalar(input: Array[Byte]): Array[Byte] =
    Sodium.r255ScalarReduce(Sodium.sha512(input))

  // ---------------------------------- server key ----------------------------------

  /** Server key pair: a secret OPRF scalar `k` and its PUBLIC commitment `pk = k · B`. `pk` is the
    * public transcript element the client verifies proofs against. */
  final case class ServerKeyPair(publicKey: Array[Byte], secretKey: Array[Byte])

  /** Generate a fresh server OPRF key. `secretKey` is a random non-zero scalar; `publicKey = k·B`. */
  def keygen(): ServerKeyPair =
    val k = Sodium.r255ScalarRandom()
    val pk = Sodium
      .r255ScalarMultBase(k)
      .getOrElse(throw new RuntimeException("VOPRF keygen: k·B failed (k was zero?)"))
    ServerKeyPair(pk, k)

  /** Recompute the public commitment `pk = k·B` for a given secret key (e.g. to publish/verify it). */
  def publicKeyOf(secretKey: Array[Byte]): Array[Byte] =
    Sodium
      .r255ScalarMultBase(secretKey)
      .getOrElse(throw new IllegalArgumentException("invalid VOPRF secret key"))

  // ---------------------------------- client: blind ----------------------------------

  /** The client's message to the server: `blinded = r · H1(x)`. */
  final case class BlindedElement(blinded: Array[Byte])

  /** Client blinding state: the secret blind `r` (kept private), the original input `x` (retained so
    * finalize can bind it into `H2`), and the `blinded` element that was actually sent. Carrying
    * `blinded` here means finalize verifies and unblinds the SAME element the state was produced for
    * — a caller cannot pair a state with a mismatched blinded element (which would otherwise yield a
    * silently-wrong-but-valid-looking output). */
  final case class BlindState(
      blind: Array[Byte],
      input: Array[Byte],
      blinded: BlindedElement
  )

  /** Blind `input`: pick random `r`, compute `blinded = r · H1(x)`. Retries the (astronomically
    * unlikely) case where `r · H1(x)` fails so the caller never sees a spurious error. Returns the
    * state (which contains the blinded element to send) — finalize consumes the same state. */
  def blind(input: Array[Byte]): BlindState =
    val hx = hashToGroup(input)
    // hx is a valid, non-identity point by construction (from_hash), but be defensive on r.
    var attempts = 0
    while attempts < 8 do
      val r = Sodium.r255ScalarRandom()
      Sodium.r255ScalarMult(r, hx) match
        case Some(blinded) =>
          return BlindState(r, input.clone(), BlindedElement(blinded))
        case None => attempts += 1
    throw new RuntimeException("VOPRF blind: scalarmult kept failing (should be impossible)")

  // ---------------------------------- server: evaluate ----------------------------------

  /** The server's response: the evaluated element `k · blinded` and a DLEQ proof `(c, s)` that the
    * same `k` relates `(B, pk)` and `(blinded, evaluated)`. */
  final case class Evaluation(evaluated: Array[Byte], proofC: Array[Byte], proofS: Array[Byte])

  /** Server evaluates a blinded element under key `k` and produces a DLEQ proof of correct
    * evaluation against its public key `pk = k·B`.
    *
    * `blinded` is ATTACKER-CONTROLLED at the server boundary, so an invalid / identity element is
    * rejected with `Left` rather than a thrown exception (no unhandled-exception / DoS surface on
    * the enclave server; symmetric with the client-side [[finalizeEval]]).
    *
    * DLEQ (Chaum–Pedersen, Fiat–Shamir non-interactive):
    *   - pick random nonce `t`; commitments `A = t·B`, `Bc = t·blinded`
    *   - challenge `c = Hs( Context ‖ pk ‖ blinded ‖ evaluated ‖ A ‖ Bc )`
    *   - response `s = t − c·k  (mod L)`
    * The client re-derives `A' = s·B + c·pk` and `Bc' = s·blinded + c·evaluated` and checks the
    * challenge recomputes — which holds iff the server used the `k` committed in `pk`.
    *
    * The transient secret heap arrays `t` and `c·k` (each of which, with the public `s`/`c`, would
    * recover `k`) never leave this method and are wiped before returning. */
  def evaluate(secretKey: Array[Byte], blinded: BlindedElement): Either[String, Evaluation] =
    if !Sodium.r255IsValidPoint(blinded.blinded) then Left("blinded element is not a valid point")
    else
      val pk = publicKeyOf(secretKey)
      Sodium.r255ScalarMult(secretKey, blinded.blinded) match
        case None => Left("k·blinded failed (invalid blinded element)")
        case Some(evaluated) =>
          // ---- DLEQ proof ----
          val t = Sodium.r255ScalarRandom()
          var ck: Array[Byte] = null
          try
            (Sodium.r255ScalarMultBase(t), Sodium.r255ScalarMult(t, blinded.blinded)) match
              case (Some(bigA), Some(bigB)) =>
                val c = challenge(pk, blinded.blinded, evaluated, bigA, bigB)
                // s = t - c*k (mod L): scalar-multiply then scalar-subtract via libsodium field ops.
                ck = Sodium.r255ScalarMulScalar(c, secretKey)
                val s = Sodium.r255ScalarSub(t, ck)
                Right(Evaluation(evaluated, c, s))
              case _ =>
                // Only reachable if t reduced to 0 (astronomically unlikely); do not leak k.
                Left("DLEQ commitment failed")
          finally
            Sodium.wipe(t)
            if ck != null then Sodium.wipe(ck)

  // ---------------------------------- client: finalize ----------------------------------

  /** Verify the DLEQ proof against the server's PUBLIC key, then unblind and finalize. The blinded
    * element that is verified and unblinded is taken from `state` itself, so it can never diverge
    * from the input/blind the state was produced for (a mismatched pair would otherwise verify
    * against one element while binding another into `H2`, yielding a silently-wrong output).
    *
    * Returns `Right(output)` with the PRF output `H2(x, k·H1(x))` iff the proof is valid; otherwise
    * `Left(reason)` — a malicious/misconfigured server (wrong key, tampered proof, tampered
    * evaluation) is REJECTED, never yielding a key. Verification comparison is constant-time. The
    * transient inverse blind `r⁻¹` is wiped before returning. */
  def finalizeEval(
      serverPublicKey: Array[Byte],
      state: BlindState,
      eval: Evaluation
  ): Either[String, Array[Byte]] =
    val blinded = state.blinded
    if !Sodium.r255IsValidPoint(serverPublicKey) then Left("invalid server public key")
    else if !Sodium.r255IsValidPoint(eval.evaluated) then Left("invalid evaluated element")
    else if !verifyProof(serverPublicKey, blinded.blinded, eval) then Left("DLEQ proof rejected")
    else
      // unblind: n = r⁻¹ · evaluated = k · H1(x)
      Sodium.r255ScalarInvert(state.blind) match
        case None => Left("blind not invertible")
        case Some(rInv) =>
          try
            Sodium.r255ScalarMult(rInv, eval.evaluated) match
              case None => Left("unblind failed")
              case Some(n) => Right(finalizeOutput(state.input, n))
          finally Sodium.wipe(rInv)

  /** Recompute the final PRF output `H2(x, n)` where `n = k·H1(x)`. 32-byte output. */
  private def finalizeOutput(input: Array[Byte], unblinded: Array[Byte]): Array[Byte] =
    Sodium.blake2b(concat(Context, tag("H2"), input, unblinded), 32, Array.emptyByteArray)

  /** Client-side DLEQ verification: recompute the challenge from `s`, `c` and the public transcript
    * and compare in constant time. */
  private def verifyProof(
      pk: Array[Byte],
      blinded: Array[Byte],
      eval: Evaluation
  ): Boolean =
    // A' = s·B + c·pk ;  B' = s·blinded + c·evaluated
    val sB = Sodium.r255ScalarMultBase(eval.proofS)
    val cPk = Sodium.r255ScalarMult(eval.proofC, pk)
    val sBl = Sodium.r255ScalarMult(eval.proofS, blinded)
    val cEv = Sodium.r255ScalarMult(eval.proofC, eval.evaluated)
    (sB, cPk, sBl, cEv) match
      case (Some(sBv), Some(cPkv), Some(sBlv), Some(cEvv)) =>
        (Sodium.r255Add(sBv, cPkv), Sodium.r255Add(sBlv, cEvv)) match
          case (Some(aPrime), Some(bPrime)) =>
            val cPrime = challenge(pk, blinded, eval.evaluated, aPrime, bPrime)
            Sodium.memcmp(cPrime, eval.proofC)
          case _ => false
      case _ => false

  /** Fiat–Shamir challenge scalar over the DLEQ transcript. */
  private def challenge(
      pk: Array[Byte],
      blinded: Array[Byte],
      evaluated: Array[Byte],
      commitA: Array[Byte],
      commitB: Array[Byte]
  ): Array[Byte] =
    hashToScalar(concat(Context, tag("DLEQ"), pk, blinded, evaluated, commitA, commitB))
