package crypto

import org.scalatest.funsuite.AnyFunSuite

/** 2HashDH VOPRF over ristretto255 (RFC 9497 verifiable mode), exercised through [[Voprf]] and the
  * libsodium ristretto255 bindings in [[Sodium]]. The group/hash primitives are libsodium's; these
  * tests prove the protocol composition (blind → evaluate+prove → verify → unblind) is correct and
  * that every tamper / wrong-key case is rejected. */
class VoprfSpec extends AnyFunSuite:

  private def bytes(s: String): Array[Byte] = s.getBytes("UTF-8")

  test("happy path: blind → evaluate → verify proof → unblind yields the PRF output"):
    val server = Voprf.keygen()
    assert(server.publicKey.length == Sodium.Ristretto255Bytes)
    assert(server.secretKey.length == Sodium.Ristretto255ScalarBytes)
    assert(Sodium.r255IsValidPoint(server.publicKey))

    val input = bytes("epoch-42 client-context")
    val (state, blinded) = Voprf.blind(input)
    val eval = Voprf.evaluate(server.secretKey, blinded)
    val out = Voprf.finalizeEval(server.publicKey, state, blinded, eval)
    assert(out.isRight, s"valid run must finalize: $out")
    assert(out.toOption.get.length == 32)

  test("determinism: same input + same key ⇒ same PRF output despite fresh random blinds"):
    val server = Voprf.keygen()
    val input = bytes("stable-input")

    def run(): Array[Byte] =
      val (st, be) = Voprf.blind(input)
      val ev = Voprf.evaluate(server.secretKey, be)
      Voprf.finalizeEval(server.publicKey, st, be, ev).toOption.get

    val a = run()
    val b = run()
    assert(a.sameElements(b), "VOPRF must be deterministic in (key, input) — blind is unobservable")

  test("different inputs ⇒ different outputs; different keys ⇒ different outputs"):
    val server = Voprf.keygen()
    val (s1, b1) = Voprf.blind(bytes("input-A"))
    val (s2, b2) = Voprf.blind(bytes("input-B"))
    val o1 = Voprf
      .finalizeEval(server.publicKey, s1, b1, Voprf.evaluate(server.secretKey, b1))
      .toOption
      .get
    val o2 = Voprf
      .finalizeEval(server.publicKey, s2, b2, Voprf.evaluate(server.secretKey, b2))
      .toOption
      .get
    assert(!o1.sameElements(o2), "distinct inputs must give distinct outputs")

    val other = Voprf.keygen()
    val (s3, b3) = Voprf.blind(bytes("input-A"))
    val o3 =
      Voprf.finalizeEval(other.publicKey, s3, b3, Voprf.evaluate(other.secretKey, b3)).toOption.get
    assert(!o1.sameElements(o3), "same input under a different key must give a different output")

  test("a TAMPERED DLEQ proof (c) is rejected"):
    val server = Voprf.keygen()
    val (st, be) = Voprf.blind(bytes("x"))
    val ev = Voprf.evaluate(server.secretKey, be)
    val badC = ev.proofC.clone(); badC(0) = (badC(0) ^ 0x01).toByte
    val tampered = ev.copy(proofC = badC)
    assert(Voprf.finalizeEval(server.publicKey, st, be, tampered) == Left("DLEQ proof rejected"))

  test("a TAMPERED DLEQ proof (s) is rejected"):
    val server = Voprf.keygen()
    val (st, be) = Voprf.blind(bytes("x"))
    val ev = Voprf.evaluate(server.secretKey, be)
    val badS = ev.proofS.clone(); badS(0) = (badS(0) ^ 0x01).toByte
    assert(Voprf.finalizeEval(server.publicKey, st, be, ev.copy(proofS = badS)).isLeft)

  test("a TAMPERED evaluated element is rejected by the proof"):
    val server = Voprf.keygen()
    val (st, be) = Voprf.blind(bytes("x"))
    val ev = Voprf.evaluate(server.secretKey, be)
    // Substitute a different valid group element as the evaluation.
    val (_, other) = Voprf.blind(bytes("y"))
    assert(Voprf.finalizeEval(server.publicKey, st, be, ev.copy(evaluated = other.blinded)).isLeft)

  test("a WRONG server public key is rejected"):
    val server = Voprf.keygen()
    val attacker = Voprf.keygen()
    val (st, be) = Voprf.blind(bytes("x"))
    val ev = Voprf.evaluate(server.secretKey, be)
    // Proof was made by `server`; verifying it against a different pk must fail.
    assert(Voprf.finalizeEval(attacker.publicKey, st, be, ev).isLeft)

  test("a server evaluating under the WRONG key cannot produce an accepting proof"):
    // Malicious server substitutes its key silently: it publishes `honest.publicKey` but evaluates
    // with a different key. The client must reject (this is the anti-partition guarantee).
    val honest = Voprf.keygen()
    val rogueKey = Voprf.keygen().secretKey
    val (st, be) = Voprf.blind(bytes("x"))
    val ev = Voprf.evaluate(rogueKey, be) // proof is consistent with rogueKey, not honest.publicKey
    assert(Voprf.finalizeEval(honest.publicKey, st, be, ev).isLeft)

  test("a malformed server public key ⇒ Left, not an exception"):
    val server = Voprf.keygen()
    val (st, be) = Voprf.blind(bytes("x"))
    val ev = Voprf.evaluate(server.secretKey, be)
    assert(Voprf.finalizeEval(new Array[Byte](32), st, be, ev).isLeft)

  test("publicKeyOf is consistent with keygen"):
    val server = Voprf.keygen()
    assert(Voprf.publicKeyOf(server.secretKey).sameElements(server.publicKey))

  test(
    "ristretto255 binding sanity: from_hash gives valid points; scalarmult obeys r·(s·B)=(r·s)·B"
  ):
    val u = Sodium.sha512(bytes("some input"))
    val p = Sodium.r255FromHash(u)
    assert(Sodium.r255IsValidPoint(p))
    val r = Sodium.r255ScalarRandom()
    val s = Sodium.r255ScalarRandom()
    val lhs = Sodium.r255ScalarMult(r, Sodium.r255ScalarMultBase(s).get).get
    val rhs = Sodium.r255ScalarMultBase(Sodium.r255ScalarMulScalar(r, s)).get
    assert(lhs.sameElements(rhs), "group homomorphism must hold via libsodium ops")

  test("memcmp is length-aware and value-correct"):
    assert(Sodium.memcmp(bytes("abc"), bytes("abc")))
    assert(!Sodium.memcmp(bytes("abc"), bytes("abd")))
    assert(!Sodium.memcmp(bytes("abc"), bytes("ab")))
