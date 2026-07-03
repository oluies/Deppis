package kem

import engine.Uint8
import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

/** Scala.js platform implementation of ML-KEM-768 (FIPS 203), the JS counterpart of the JVM's
  * liboqs binding (`crypto.Oqs`).
  *
  * The lattice math is provided by **@noble/post-quantum** (audited, widely used): a vetted
  * primitive — NOT hand-rolled (Constitution I) — exactly as **@noble/hashes** provides the KDF's
  * HMAC-SHA256 (see [[kdf.Kdf]]). We implement no lattice arithmetic ourselves.
  *
  * The dependency is pinned to an exact version in the repo `package.json` (Constitution XI). Under
  * Node it resolves from `node_modules`; a browser build resolves the bare `@noble/...` specifier
  * via a bundler or import map (noble is pure JS, browser-safe).
  *
  * FIPS 203 ML-KEM-768 sizes: publicKey 1184, secretKey 2400, ciphertext 1088, sharedSecret 32.
  *
  * Interoperability with the JVM (liboqs) side is proven in `KemJsSpec` by reproducing the exact
  * NIST ACVP decapsulation known-answer vector that the JVM pins in `crypto.OqsKatSpec`: if both
  * implementations match the same FIPS 203 vector, they interoperate. */
@js.native
@JSImport("@noble/post-quantum/ml-kem.js", JSImport.Namespace)
private object MlKemModule extends js.Object:
  val ml_kem768: MlKem768 = js.native

@js.native
private trait MlKem768 extends js.Object:
  def keygen(): KeyPairJs = js.native
  def encapsulate(publicKey: Uint8Array): EncapsJs = js.native
  def decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array = js.native

@js.native
private trait KeyPairJs extends js.Object:
  val publicKey: Uint8Array = js.native
  val secretKey: Uint8Array = js.native

@js.native
private trait EncapsJs extends js.Object:
  val cipherText: Uint8Array = js.native
  val sharedSecret: Uint8Array = js.native

/** ML-KEM-768 key encapsulation, mirroring the JVM `crypto.Oqs` surface: keypair / encaps / decaps.
  */
object Kem:
  /** Generate a fresh ML-KEM-768 keypair. Returns `(publicKey, secretKey)`. */
  def keypair(): (Array[Byte], Array[Byte]) =
    val kp = MlKemModule.ml_kem768.keygen()
    (Uint8.toBytes(kp.publicKey), Uint8.toBytes(kp.secretKey))

  /** Encapsulate to `publicKey`. Returns `(ciphertext, sharedSecret)`. */
  def encaps(publicKey: Array[Byte]): (Array[Byte], Array[Byte]) =
    val e = MlKemModule.ml_kem768.encapsulate(Uint8.toJs(publicKey))
    (Uint8.toBytes(e.cipherText), Uint8.toBytes(e.sharedSecret))

  /** Decapsulate `ciphertext` with `secretKey`, yielding the shared secret. Deterministic; a
    * modified ciphertext yields a pseudo-random secret (FIPS 203 IND-CCA2 implicit rejection). */
  def decaps(ciphertext: Array[Byte], secretKey: Array[Byte]): Array[Byte] =
    Uint8.toBytes(MlKemModule.ml_kem768.decapsulate(Uint8.toJs(ciphertext), Uint8.toJs(secretKey)))
