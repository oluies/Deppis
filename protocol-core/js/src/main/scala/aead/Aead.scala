package aead

import engine.Uint8
import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

/** ChaCha20-Poly1305 AEAD (Scala.js) via **@noble/ciphers** — audited, widely used, synchronous and
  * browser-safe (Constitution I). RFC 8439 IETF: 32-byte key, 12-byte nonce, 16-byte appended tag,
  * no AAD — byte-for-byte identical to the JVM JCA build, which a cross-platform KAT pins. */
@js.native
@JSImport("@noble/ciphers/chacha", "chacha20poly1305")
private object chacha20poly1305 extends js.Object:
  def apply(key: Uint8Array, nonce: Uint8Array): Cipher = js.native

@js.native
private trait Cipher extends js.Object:
  def encrypt(plaintext: Uint8Array): Uint8Array = js.native
  def decrypt(ciphertext: Uint8Array): Uint8Array = js.native

object Aead:
  val KeyBytes: Int = 32
  val NonceBytes: Int = 12
  val TagBytes: Int = 16

  def seal(key: Array[Byte], nonce: Array[Byte], plaintext: Array[Byte]): Array[Byte] =
    Uint8.toBytes(
      chacha20poly1305(Uint8.toJs(key), Uint8.toJs(nonce)).encrypt(Uint8.toJs(plaintext))
    )

  def open(key: Array[Byte], nonce: Array[Byte], ciphertext: Array[Byte]): Option[Array[Byte]] =
    try
      Some(
        Uint8.toBytes(
          chacha20poly1305(Uint8.toJs(key), Uint8.toJs(nonce)).decrypt(Uint8.toJs(ciphertext))
        )
      )
    catch case _: Throwable => None
