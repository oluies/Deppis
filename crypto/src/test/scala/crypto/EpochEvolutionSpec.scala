package crypto

import org.scalatest.funsuite.AnyFunSuite

/** US7 — verifiable per-epoch key evolution over the [[Voprf]]. Proves the round-trip, the
  * verifiability (wrong key / tampered proof rejected), forward secrecy across epochs (a past
  * epoch key is not derivable from the current one), and expected determinism. */
class EpochEvolutionSpec extends AnyFunSuite:

  private def ctx(s: String): Array[Byte] = s.getBytes("UTF-8")

  /** Server evaluate must succeed on a well-formed blinded element (unwrap the Either). */
  private def serverEval(secretKey: Array[Byte], blinded: Voprf.BlindedElement): Voprf.Evaluation =
    EpochEvolution.serverEvolve(secretKey, blinded) match
      case Right(e) => e
      case Left(err) => fail(s"serverEvolve should succeed on a valid blinded element: $err")

  private def evolve(server: Voprf.ServerKeyPair, context: Array[Byte], epoch: Long): Array[Byte] =
    val req = EpochEvolution.beginEvolve(context, epoch)
    val ev = serverEval(server.secretKey, req.blinded)
    EpochEvolution.completeEvolve(server.publicKey, req, ev) match
      case Right(k) => k
      case Left(err) => fail(s"evolve failed: $err")

  test("round-trip: a client evolves an epoch key and it is 32 bytes"):
    val server = EpochEvolution.serverKeygen()
    val key = evolve(server, ctx("client-1"), epoch = 5L)
    assert(key.length == EpochEvolution.EpochKeyBytes)

  test("determinism: same (client, epoch, server key) ⇒ same epoch key across independent runs"):
    val server = EpochEvolution.serverKeygen()
    val k1 = evolve(server, ctx("client-1"), 7L)
    val k2 = evolve(server, ctx("client-1"), 7L)
    assert(k1.sameElements(k2), "epoch key must be reproducible for the same input and key")

  test("forward secrecy across epochs: consecutive epoch keys are independent"):
    val server = EpochEvolution.serverKeygen()
    val client = ctx("client-1")
    val keys = (0L until 6L).map(e => evolve(server, client, e)).toVector
    // All distinct...
    for i <- keys.indices; j <- keys.indices if i != j do
      assert(!keys(i).sameElements(keys(j)), s"epoch $i and $j keys must differ")
    // ...and a later key reveals nothing that lets you reconstruct an earlier one: the derivation
    // is a one-way KDF of an independent PRF output, so no XOR/prefix relation holds.
    val e2 = keys(2)
    val e5 = keys(5)
    assert(!e2.sameElements(e5))
    // A trivial "chained" relation (e5 == KDF(e2)) must NOT hold — keys are not a hash chain.
    val chained = Crypto.kdf(
      e2,
      "Deppis-epoch-evolution-v1".getBytes("UTF-8"),
      "epoch-key".getBytes("UTF-8"),
      EpochEvolution.EpochKeyBytes
    )
    assert(!chained.sameElements(e5))

  test("distinct clients get distinct epoch keys for the same epoch (no cross-client linkage)"):
    val server = EpochEvolution.serverKeygen()
    val a = evolve(server, ctx("client-A"), 3L)
    val b = evolve(server, ctx("client-B"), 3L)
    assert(!a.sameElements(b))

  test("verifiable: a malicious server using the WRONG key is rejected (anti-partition)"):
    val honest = EpochEvolution.serverKeygen()
    val rogueKey = EpochEvolution.serverKeygen().secretKey
    val req = EpochEvolution.beginEvolve(ctx("client-1"), 9L)
    // Server publishes honest.publicKey but evaluates under a rogue key.
    val ev = serverEval(rogueKey, req.blinded)
    assert(EpochEvolution.completeEvolve(honest.publicKey, req, ev).isLeft)

  test("verifiable: a tampered evaluation/proof is rejected, yielding NO key"):
    val server = EpochEvolution.serverKeygen()
    val req = EpochEvolution.beginEvolve(ctx("client-1"), 1L)
    val ev = serverEval(server.secretKey, req.blinded)
    val badC = ev.proofC.clone(); badC(0) = (badC(0) ^ 0x01).toByte
    assert(EpochEvolution.completeEvolve(server.publicKey, req, ev.copy(proofC = badC)).isLeft)

  test("obliviousness sanity: the server's blinded input reveals no epoch structure"):
    // Two different epochs for the same client produce unrelated blinded elements (fresh blinds),
    // so the server cannot correlate rounds by the blinded value. (Statistical check: they differ.)
    val r1 = EpochEvolution.beginEvolve(ctx("client-1"), 1L)
    val r2 = EpochEvolution.beginEvolve(ctx("client-1"), 2L)
    assert(!r1.blinded.blinded.sameElements(r2.blinded.blinded))

  test("consistency: finalize verifies+unblinds the SAME blinded element the state was made for"):
    // The blinded element is carried inside BlindState, so a client cannot finalize a state against
    // an evaluation produced for a DIFFERENT blinded element and silently obtain a wrong key: the
    // evaluation for req2 (a different blind) does not verify against req1's state.
    val server = EpochEvolution.serverKeygen()
    val req1 = EpochEvolution.beginEvolve(ctx("client-1"), 1L)
    val req2 = EpochEvolution.beginEvolve(ctx("client-1"), 1L) // same input, fresh blind
    val evForReq2 = serverEval(server.secretKey, req2.blinded)
    // Pairing req1's state with req2's evaluation must be rejected (DLEQ is over req2.blinded).
    assert(EpochEvolution.completeEvolve(server.publicKey, req1, evForReq2).isLeft)

  test("KAT regression: fixed (server key, client, epoch) pins the epoch key"):
    // Deterministic in (key, input): pin the derived epoch key for a FIXED server key so a silent
    // change to the VOPRF construction, Encoding.lengthPrefixed, the epoch input framing, or the
    // KDF salt/info is caught. Expected value computed once from this code and pinned.
    val secretKey = new Array[Byte](Sodium.Ristretto255ScalarBytes)
    var i = 0
    while i < 16 do { secretKey(i) = (i + 1).toByte; i += 1 } // 01 02 … 10, rest zero → < L
    val publicKey = Voprf.publicKeyOf(secretKey)

    val req = EpochEvolution.beginEvolve(ctx("kat-client"), 3L)
    val ev = serverEval(secretKey, req.blinded)
    val key = EpochEvolution.completeEvolve(publicKey, req, ev).toOption.get
    val hex = key.map(b => f"${b & 0xff}%02x").mkString
    assert(hex == EpochEvolutionSpec.KatEpochKeyHex, s"epoch-key KAT drift: got $hex")

object EpochEvolutionSpec:
  /** Pinned epoch key (hex) for secretKey = 01 02 … 10 ‖ 0…0, client "kat-client", epoch 3.
    * Regenerate ONLY on a deliberate, reviewed change to the construction. */
  val KatEpochKeyHex: String = "71b1608986e79fbb74b2b1137b7dcbd604a9cf6f5bfcf218797a2fede1fc05f6"
