package crypto

import org.scalatest.funsuite.AnyFunSuite

/** 2HashDH VOPRF over ristretto255 (RFC 9497 verifiable mode), exercised through [[Voprf]] and the
  * libsodium ristretto255 bindings in [[Sodium]]. The group/hash primitives are libsodium's; these
  * tests prove the protocol composition (blind → evaluate+prove → verify → unblind) is correct and
  * that every tamper / wrong-key / malformed-input case is rejected. */
class VoprfSpec extends AnyFunSuite:

  private def bytes(s: String): Array[Byte] = s.getBytes("UTF-8")

  /** Server evaluate must succeed on a well-formed blinded element (unwrap the Either). */
  private def evalOf(secretKey: Array[Byte], be: Voprf.BlindedElement): Voprf.Evaluation =
    Voprf.evaluate(secretKey, be) match
      case Right(e) => e
      case Left(err) => fail(s"evaluate should succeed on a valid blinded element: $err")

  test("happy path: blind → evaluate → verify proof → unblind yields the PRF output"):
    val server = Voprf.keygen()
    assert(server.publicKey.length == Sodium.Ristretto255Bytes)
    assert(server.secretKey.length == Sodium.Ristretto255ScalarBytes)
    assert(Sodium.r255IsValidPoint(server.publicKey))

    val input = bytes("epoch-42 client-context")
    val state = Voprf.blind(input)
    val eval = evalOf(server.secretKey, state.blinded)
    val out = Voprf.finalizeEval(server.publicKey, state, eval)
    assert(out.isRight, s"valid run must finalize: $out")
    assert(out.toOption.get.length == 32)

  test("determinism: same input + same key ⇒ same PRF output despite fresh random blinds"):
    val server = Voprf.keygen()
    val input = bytes("stable-input")

    def run(): Array[Byte] =
      val st = Voprf.blind(input)
      val ev = evalOf(server.secretKey, st.blinded)
      Voprf.finalizeEval(server.publicKey, st, ev).toOption.get

    val a = run()
    val b = run()
    assert(a.sameElements(b), "VOPRF must be deterministic in (key, input) — blind is unobservable")

  test("different inputs ⇒ different outputs; different keys ⇒ different outputs"):
    val server = Voprf.keygen()
    val s1 = Voprf.blind(bytes("input-A"))
    val s2 = Voprf.blind(bytes("input-B"))
    val o1 =
      Voprf.finalizeEval(server.publicKey, s1, evalOf(server.secretKey, s1.blinded)).toOption.get
    val o2 =
      Voprf.finalizeEval(server.publicKey, s2, evalOf(server.secretKey, s2.blinded)).toOption.get
    assert(!o1.sameElements(o2), "distinct inputs must give distinct outputs")

    val other = Voprf.keygen()
    val s3 = Voprf.blind(bytes("input-A"))
    val o3 =
      Voprf.finalizeEval(other.publicKey, s3, evalOf(other.secretKey, s3.blinded)).toOption.get
    assert(!o1.sameElements(o3), "same input under a different key must give a different output")

  test("a TAMPERED DLEQ proof (c) is rejected"):
    val server = Voprf.keygen()
    val st = Voprf.blind(bytes("x"))
    val ev = evalOf(server.secretKey, st.blinded)
    val badC = ev.proofC.clone(); badC(0) = (badC(0) ^ 0x01).toByte
    assert(
      Voprf.finalizeEval(server.publicKey, st, ev.copy(proofC = badC)) == Left(
        "DLEQ proof rejected"
      )
    )

  test("a TAMPERED DLEQ proof (s) is rejected"):
    val server = Voprf.keygen()
    val st = Voprf.blind(bytes("x"))
    val ev = evalOf(server.secretKey, st.blinded)
    val badS = ev.proofS.clone(); badS(0) = (badS(0) ^ 0x01).toByte
    assert(Voprf.finalizeEval(server.publicKey, st, ev.copy(proofS = badS)).isLeft)

  test("a TAMPERED evaluated element is rejected by the proof"):
    val server = Voprf.keygen()
    val st = Voprf.blind(bytes("x"))
    val ev = evalOf(server.secretKey, st.blinded)
    // Substitute a different valid group element as the evaluation.
    val other = Voprf.blind(bytes("y"))
    assert(
      Voprf.finalizeEval(server.publicKey, st, ev.copy(evaluated = other.blinded.blinded)).isLeft
    )

  test("a WRONG server public key is rejected"):
    val server = Voprf.keygen()
    val attacker = Voprf.keygen()
    val st = Voprf.blind(bytes("x"))
    val ev = evalOf(server.secretKey, st.blinded)
    // Proof was made by `server`; verifying it against a different pk must fail.
    assert(Voprf.finalizeEval(attacker.publicKey, st, ev).isLeft)

  test("a server evaluating under the WRONG key cannot produce an accepting proof"):
    // Malicious server substitutes its key silently: it publishes `honest.publicKey` but evaluates
    // with a different key. The client must reject (this is the anti-partition guarantee).
    val honest = Voprf.keygen()
    val rogueKey = Voprf.keygen().secretKey
    val st = Voprf.blind(bytes("x"))
    val ev = evalOf(rogueKey, st.blinded) // proof is consistent with rogueKey, not honest.publicKey
    assert(Voprf.finalizeEval(honest.publicKey, st, ev).isLeft)

  test("a malformed server public key ⇒ Left, not an exception"):
    val server = Voprf.keygen()
    val st = Voprf.blind(bytes("x"))
    val ev = evalOf(server.secretKey, st.blinded)
    assert(Voprf.finalizeEval(new Array[Byte](32), st, ev).isLeft)

  test("server evaluate rejects a MALFORMED / identity blinded element with Left (no throw)"):
    // `blinded` is attacker-controlled at the server boundary; it must never throw (DoS surface).
    val server = Voprf.keygen()
    // all-zero encoding is the ristretto255 identity → not a valid OPRF blinded element.
    val identity = new Array[Byte](Sodium.Ristretto255Bytes)
    assert(Voprf.evaluate(server.secretKey, Voprf.BlindedElement(identity)).isLeft)
    // a non-canonical / garbage 32-byte string is also rejected without an exception.
    val garbage = Array.fill[Byte](Sodium.Ristretto255Bytes)(0xff.toByte)
    assert(Voprf.evaluate(server.secretKey, Voprf.BlindedElement(garbage)).isLeft)

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

  test("KAT regression: fixed (key, input) pins the PRF output (domain-separation/framing drift)"):
    // The VOPRF is deterministic in (key, input) despite random blinds. Pin the output for a FIXED
    // server key so that a silent change to Context, Encoding.lengthPrefixed, H1/H2, or the group
    // maps is caught (all of which would shift the output). Ristretto255 encodes points canonically,
    // so a fixed scalar key yields a fixed public key and a fixed PRF output across runs/platforms.
    //
    // The key is a canonical scalar < L (fits in the low bytes; high bytes zero), so it is a valid
    // reduced scalar. The expected value below was computed once from this code and pinned.
    val secretKey = new Array[Byte](Sodium.Ristretto255ScalarBytes)
    var i = 0
    while i < 16 do { secretKey(i) = (i + 1).toByte; i += 1 } // 01 02 ... 10, rest zero → < L
    val publicKey = Voprf.publicKeyOf(secretKey)
    val input = bytes("Deppis-KAT-input")

    val st = Voprf.blind(input)
    val ev = evalOf(secretKey, st.blinded)
    val out = Voprf.finalizeEval(publicKey, st, ev).toOption.get
    val hex = out.map(b => f"${b & 0xff}%02x").mkString

    assert(hex == VoprfSpec.KatPrfOutputHex, s"VOPRF KAT drift: got $hex")

object VoprfSpec:
  /** Pinned PRF output (hex) for secretKey = 01 02 … 10 ‖ 0…0 and input "Deppis-KAT-input".
    * Regenerate ONLY on a deliberate, reviewed change to the construction. */
  val KatPrfOutputHex: String = "20fb36c4aa36015236de81b8afb780ceb37f2f3abd1836431c242a7311c1c0e5"
