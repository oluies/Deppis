package engine

import frame.Frame
import org.scalatest.funsuite.AnyFunSuite

import java.nio.charset.StandardCharsets.UTF_8

/** SINGLE-SOURCED cross-platform test that the DH double ratchet DROPS a frame carrying a low-order /
  * non-canonical peer ratchet header key instead of crashing. Compiled into BOTH the JVM
  * `protocolCore` build (JCA X25519/AEAD/HMAC) and the Scala.js `protocolCoreJS` build (`@noble`) via
  * each project's `crosstest/src/test` dir (see build.sbt), so the ratchet's peer-key handling is
  * asserted ONCE and holds identically on both platforms.
  *
  * This is the roborev-flagged cross-platform oracle, closed at the ratchet's own DH primitive: a
  * header sealed under the responder's bootstrap header key `hka` (both sides derive it from the
  * shared content root) but carrying an attacker-chosen low-order / non-canonical ratchet public key
  * makes `X25519.sharedSecret` throw `PeerKeyRejected`; `decrypt` must treat it as an undecryptable
  * carrier (None), with no state mutation and no crash. */
class DoubleRatchetRejectionCrossSpec extends AnyFunSuite:

  private def contentRoot(seed: Byte): Array[Byte] = Array.fill(32)(seed)
  private def inner(msg: String): Array[Byte] =
    Frame.pad(msg.getBytes(UTF_8), DoubleRatchet.InnerSize).toOption.get
  private def text(inner: Array[Byte]): String =
    new String(Frame.unpad(inner, DoubleRatchet.InnerSize).toOption.get, UTF_8)

  test(
    "a low-order / non-canonical peer ratchet header key is dropped as undecryptable, not a crash"
  ):
    val root = contentRoot(9)
    val hka = kdf.Kdf.hmacSha256(root, "dr/hdr/a".getBytes(UTF_8)) // == responder's initial nhkr
    def malicious(dhPub: Array[Byte]): Array[Byte] =
      val header = dhPub ++ Array.fill[Byte](8)(0) // PN=0, Ns=0
      val nonce = Array.fill[Byte](12)(0x11.toByte)
      val sealedHeader = aead.Aead.seal(hka, nonce, header)
      val body = Array.fill[Byte](DoubleRatchet.WireSize - 12 - sealedHeader.length)(0x5a.toByte)
      nonce ++ sealedHeader ++ body
    val lowOrder = new Array[Byte](32) // all-zero u: order-2, canonical, all-zero ECDH
    val nonCanonical = // u = p (edff…7f) — rejected by the canonical range check
      val a = Array.fill[Byte](32)(0xff.toByte); a(0) = 0xed.toByte; a(31) = 0x7f.toByte; a
    val bob = DoubleRatchet.initResponder(root)
    assert(
      bob.decrypt(malicious(lowOrder)).isEmpty,
      "low-order peer ratchet key ⇒ dropped, no crash"
    )
    assert(bob.decrypt(malicious(nonCanonical)).isEmpty, "non-canonical peer ratchet key ⇒ dropped")
    // State intact: the genuine first frame from the matching initiator still decrypts.
    val alice = DoubleRatchet.initInitiator(root)
    assert(bob.decrypt(alice.encrypt(inner("real"))).map(text).contains("real"))
