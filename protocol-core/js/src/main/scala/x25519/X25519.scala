package x25519

import engine.Uint8
import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

/** X25519 ECDH (Scala.js) via **@noble/curves** — audited, synchronous, browser-safe (Constitution I).
  * RFC 7748: raw 32-byte little-endian keys, byte-for-byte identical to the JVM JCA build, which a
  * cross-platform KAT pins (`x25519.X25519Spec` on the JVM, `X25519JsSpec` here). */
@js.native
@JSImport("@noble/curves/ed25519", "x25519")
private object nobleX25519 extends js.Object:
  def getPublicKey(privateKey: Uint8Array): Uint8Array = js.native
  def getSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array = js.native
  val utils: js.Dynamic = js.native

object X25519:
  val KeyBytes: Int = 32

  /** A fresh `(privateKey, publicKey)` pair, raw 32-byte each. */
  def generateKeyPair(): (Array[Byte], Array[Byte]) =
    val priv = Uint8.toBytes(nobleX25519.utils.randomPrivateKey().asInstanceOf[Uint8Array])
    (priv, publicKey(priv))

  /** The raw public key for a raw private key (deterministic): `X25519(priv, base)`. */
  def publicKey(privateKey: Array[Byte]): Array[Byte] =
    Uint8.toBytes(nobleX25519.getPublicKey(Uint8.toJs(privateKey)))

  /** The 32-byte X25519 shared secret between our raw private key and a raw peer public key.
    *
    * Peer keys arrive in headers / ciphertexts and are attacker-controllable, so the acceptance set
    * and the rejection exception are UNIFORM across platforms (pinned by `X25519Spec` /
    * `X25519JsSpec` + the shared `X25519RejectionCrossSpec`), matching the JVM JCA build byte-for-byte
    * on valid inputs:
    *   - a non-canonical encoding whose (bit-255-masked, little-endian) u-coordinate is `>= p` is
    *     rejected up front by the shared `CanonicalU.requireCanonical` (`PeerKeyRejected`);
    *   - a degenerate / low-order peer key (all-zero ECDH result) is rejected by `@noble/curves`
    *     throwing, which we NORMALIZE to `PeerKeyRejected` — the same dedicated
    *     `IllegalArgumentException` subtype the JVM build raises, so callers (the classical
    *     `DoubleRatchet`, the hybrid `kem.HybridKem`) treat a rejected peer key uniformly on both
    *     platforms (an undecryptable / carrier frame).
    * A wrong-length PRIVATE key is a LOCAL key-management error, not a peer rejection, so it is
    * validated up front with a plain `IllegalArgumentException` (a distinct message) BEFORE the ECDH —
    * so noble's throw can only ever mean a peer-key rejection, never a mislabeled local-key bug. */
  def sharedSecret(privateKey: Array[Byte], peerPublic: Array[Byte]): Array[Byte] =
    require(privateKey.length == KeyBytes, s"X25519 private key must be $KeyBytes bytes")
    CanonicalU.requireCanonical(peerPublic)
    try Uint8.toBytes(nobleX25519.getSharedSecret(Uint8.toJs(privateKey), Uint8.toJs(peerPublic)))
    catch
      case e: js.JavaScriptException =>
        throw new PeerKeyRejected(s"X25519 peer key rejected: ${e.getMessage}", e)
