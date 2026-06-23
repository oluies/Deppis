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

  /** The 32-byte X25519 shared secret between our raw private key and a raw peer public key. */
  def sharedSecret(privateKey: Array[Byte], peerPublic: Array[Byte]): Array[Byte] =
    Uint8.toBytes(nobleX25519.getSharedSecret(Uint8.toJs(privateKey), Uint8.toJs(peerPublic)))
