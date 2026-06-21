package aead

import org.scalatest.funsuite.AnyFunSuite

/** ChaCha20-Poly1305 AEAD (JVM, JCA). Round-trip + auth-failure + a static known-answer vector that
  * the JS (`@noble/ciphers`) build must reproduce byte-for-byte (cross-platform KAT). */
class AeadSpec extends AnyFunSuite:

  private val key = Array.tabulate(32)(_.toByte)
  private val nonce = Array.tabulate(12)(_.toByte)

  test("seal/open round-trips"):
    val pt = "hello aead".getBytes("UTF-8")
    val ct = Aead.seal(key, nonce, pt)
    assert(ct.length == pt.length + Aead.TagBytes)
    assert(Aead.open(key, nonce, ct).map(new String(_, "UTF-8")).contains("hello aead"))

  test("a tampered ciphertext fails authentication (None, no secret-dependent message)"):
    val ct = Aead.seal(key, nonce, "secret".getBytes("UTF-8"))
    val bad = ct.updated(ct.length - 1, (ct.last ^ 0x01).toByte)
    assert(Aead.open(key, nonce, bad).isEmpty)
    assert(Aead.open(key.updated(0, (key(0) ^ 0x01).toByte), nonce, ct).isEmpty) // wrong key

  test("known-answer vector (must match the JS @noble/ciphers build, byte for byte)"):
    val ct = Aead.seal(key, nonce, "the quick brown fox".getBytes("UTF-8"))
    val hex = ct.map(b => f"${b & 0xff}%02x").mkString
    assert(hex == "fd936d205862cc23dca35d81f76a6043af1fca4de50f9de09114e57e9d5995a04f2dc0")
