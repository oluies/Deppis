package engine

import frame.Frame
import org.scalatest.funsuite.AnyFunSuite

import java.nio.charset.StandardCharsets.UTF_8

/** The DH double ratchet under Node (`@noble` X25519/AEAD/HMAC) — a focused mirror of
  * `engine.DoubleRatchetSpec` (the JS project's test sources are wired to `js/src/test` only, so the
  * shared spec does NOT run here; see `build.sbt`). Re-asserts the core invariants on JS so the
  * cross-platform parity the ratchet depends on — same wire format, same key schedule, identical
  * roundtrips — is pinned on both platforms, just like `AeadJsSpec` / `X25519JsSpec`. */
class DoubleRatchetJsSpec extends AnyFunSuite:

  private def contentRoot(seed: Byte): Array[Byte] = Array.fill(32)(seed)
  private def pair(seed: Byte = 7): (DoubleRatchet, DoubleRatchet) =
    (DoubleRatchet.initInitiator(contentRoot(seed)), DoubleRatchet.initResponder(contentRoot(seed)))
  private def inner(msg: String): Array[Byte] =
    Frame.pad(msg.getBytes(UTF_8), DoubleRatchet.InnerSize).toOption.get
  private def text(inner: Array[Byte]): String =
    new String(Frame.unpad(inner, DoubleRatchet.InnerSize).toOption.get, UTF_8)

  test("bootstrap + first message roundtrips on JS"):
    val (alice, bob) = pair()
    assert(alice.canSend && !bob.canSend)
    assert(bob.decrypt(alice.encrypt(inner("hello"))).map(text).contains("hello"))
    assert(bob.canSend)

  test("bidirectional ping-pong heals with fresh DH keys on JS"):
    val (alice, bob) = pair()
    assert(bob.decrypt(alice.encrypt(inner("a1"))).map(text).contains("a1"))
    val bobPub1 = bob.sendingPublicKey
    assert(alice.decrypt(bob.encrypt(inner("b1"))).map(text).contains("b1"))
    assert(bob.decrypt(alice.encrypt(inner("a2"))).map(text).contains("a2"))
    assert(!bobPub1.sameElements(bob.sendingPublicKey), "ratchet key changes across DH steps")

  test("out-of-order delivery recovered via skipped keys on JS"):
    val (alice, bob) = pair()
    val w0 = alice.encrypt(inner("m0"))
    val w1 = alice.encrypt(inner("m1"))
    val w2 = alice.encrypt(inner("m2"))
    assert(bob.decrypt(w0).map(text).contains("m0"))
    assert(bob.decrypt(w2).map(text).contains("m2"))
    assert(bob.decrypt(w1).map(text).contains("m1"))

  test("header encryption removes the linking tag on JS"):
    val (alice, bob) = pair()
    assert(bob.decrypt(alice.encrypt(inner("x"))).map(text).contains("x"))
    assert(alice.decrypt(bob.encrypt(inner("y"))).map(text).contains("y"))
    val h = (0 until 3).map(i => alice.encrypt(inner(s"c-$i")).slice(12, 12 + 56).toVector)
    assert(h.distinct.size == 3)

  test("carrier / garbage frame returns None and leaves the ratchet intact on JS"):
    val (alice, bob) = pair()
    assert(bob.decrypt(alice.encrypt(inner("real"))).map(text).contains("real"))
    assert(bob.decrypt(Array.fill[Byte](DoubleRatchet.WireSize)(0x5a.toByte)).isEmpty)
    assert(bob.decrypt(alice.encrypt(inner("after"))).map(text).contains("after"))

  test("a valid header with a tampered body leaves the ratchet intact on JS (atomic receive)"):
    val (alice, bob) = pair()
    val w = alice.encrypt(inner("intact?"))
    val bad = w.clone()
    bad(DoubleRatchet.WireSize - 1) = (bad(DoubleRatchet.WireSize - 1) ^ 0x01).toByte
    assert(bob.decrypt(bad).isEmpty)
    assert(bob.decrypt(w).map(text).contains("intact?"))

  test("a tampered body on a stashed (out-of-order) frame does not consume the stashed key on JS"):
    val (alice, bob) = pair()
    val w0 = alice.encrypt(inner("m0"))
    val w1 = alice.encrypt(inner("m1"))
    val w2 = alice.encrypt(inner("m2"))
    assert(bob.decrypt(w0).map(text).contains("m0"))
    assert(bob.decrypt(w2).map(text).contains("m2")) // stashes m1's key
    val bad1 = w1.clone()
    bad1(DoubleRatchet.WireSize - 1) = (bad1(DoubleRatchet.WireSize - 1) ^ 0x01).toByte
    assert(bob.decrypt(bad1).isEmpty)
    assert(bob.decrypt(w1).map(text).contains("m1"))

  test(
    "low-order / non-canonical peer ratchet header key dropped as undecryptable on JS (no crash)"
  ):
    // Mirror of the JVM assertion: a header sealed under the responder's bootstrap key `hka` (derived
    // from the shared content root) but carrying an attacker-chosen low-order / non-canonical ratchet
    // public key. `X25519.sharedSecret` throws IllegalArgumentException; `decrypt` must DROP it (None)
    // with no state mutation — the cross-platform oracle, closed at the ratchet's DH primitive.
    val root = contentRoot(9)
    val hka = kdf.Kdf.hmacSha256(root, "dr/hdr/a".getBytes(UTF_8)) // == responder's initial nhkr
    def malicious(dhPub: Array[Byte]): Array[Byte] =
      val header = dhPub ++ Array.fill[Byte](8)(0) // PN=0, Ns=0
      val nonce = Array.fill[Byte](12)(0x11.toByte)
      val sealedHeader = aead.Aead.seal(hka, nonce, header)
      val body = Array.fill[Byte](DoubleRatchet.WireSize - 12 - sealedHeader.length)(0x5a.toByte)
      nonce ++ sealedHeader ++ body
    val lowOrder = new Array[Byte](32) // all-zero u: order-2, canonical, all-zero ECDH
    val nonCanonical =
      val a = Array.fill[Byte](32)(0xff.toByte); a(0) = 0xed.toByte; a(31) = 0x7f.toByte; a
    val bob = DoubleRatchet.initResponder(root)
    assert(
      bob.decrypt(malicious(lowOrder)).isEmpty,
      "low-order peer ratchet key ⇒ dropped, no crash"
    )
    assert(bob.decrypt(malicious(nonCanonical)).isEmpty, "non-canonical peer ratchet key ⇒ dropped")
    val alice = DoubleRatchet.initInitiator(root)
    assert(bob.decrypt(alice.encrypt(inner("real"))).map(text).contains("real"))
