package kdf

import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

/** Scala.js platform implementation of [[Kdf]] — the JS counterpart of the JVM's JCA version.
  *
  * HMAC-SHA256 is provided by Node's built-in `crypto` module (OpenSSL-backed): a vetted primitive,
  * NOT hand-rolled (Constitution I), and **synchronous**, so the cross-compiled `Handshake`/engine
  * logic is byte-for-byte identical to the JVM build that the tests validate. The JS engine
  * therefore runs under a Node-compatible runtime.
  *
  * (Browser targets have no `crypto` module; a Web Crypto `SubtleCrypto` facade — which is async —
  * is the documented follow-up for a browser bundle. It does not change this signature's callers
  * because the Dart bridge is already Future/stream-based.) */
@js.native
@JSImport("crypto", JSImport.Namespace)
private object NodeCrypto extends js.Object:
  def createHmac(algorithm: String, key: Uint8Array): Hmac = js.native

@js.native
private trait Hmac extends js.Object:
  def update(data: Uint8Array): Hmac = js.native
  def digest(): Uint8Array           = js.native // no encoding arg → a Buffer (Uint8Array)

object Kdf:
  def hmacSha256(key: Array[Byte], info: Array[Byte]): Array[Byte] =
    val h = NodeCrypto.createHmac("sha256", toU8(key))
    h.update(toU8(info))
    toBytes(h.digest())

  private def toU8(a: Array[Byte]): Uint8Array =
    val u = new Uint8Array(a.length)
    var i = 0
    while i < a.length do
      u(i) = (a(i) & 0xff).toShort
      i += 1
    u

  private def toBytes(u: Uint8Array): Array[Byte] =
    val out = new Array[Byte](u.length)
    var i = 0
    while i < u.length do
      out(i) = u(i).toByte
      i += 1
    out
