package kdf

import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

/** Scala.js platform implementation of [[Kdf]] — the JS counterpart of the JVM's JCA version.
  *
  * HMAC-SHA256 is provided by **@noble/hashes** (audited, widely used): a vetted primitive — NOT
  * hand-rolled (Constitution I) — that is **synchronous** AND **browser-compatible** (pure JS, no
  * Node built-ins). So the cross-compiled `Handshake`/engine logic is byte-for-byte identical to the
  * JVM build the tests validate, and the same bundle loads in a browser (Flutter web) as well as
  * Node — unlike the earlier Node-`crypto` facade, which was Node-only.
  *
  * The dependency is pinned in the repo `package.json` (Constitution XI). Under Node it resolves
  * from `node_modules`; a browser build resolves the bare `@noble/...` specifiers via a bundler or
  * import map (the bundle itself is browser-safe). */
@js.native
@JSImport("@noble/hashes/hmac", JSImport.Namespace)
private object HmacModule extends js.Object:
  def hmac(hash: js.Any, key: Uint8Array, msg: Uint8Array): Uint8Array = js.native

@js.native
@JSImport("@noble/hashes/sha256", JSImport.Namespace)
private object Sha256Module extends js.Object:
  val sha256: js.Any = js.native

object Kdf:
  def hmacSha256(key: Array[Byte], info: Array[Byte]): Array[Byte] =
    // Zero our own transient Uint8Array copies of the inputs once noble has read them. For secret
    // callers (e.g. KeySchedule.pqContentRoot, which mixes the KEM shared secret into `info`) these
    // copies are otherwise un-wiped heap duplicates of secret material (Constitution II); harmless
    // for the public-label callers. noble.hmac consumes the inputs synchronously, so wiping after it
    // returns does not affect the output.
    val kU = toU8(key)
    val iU = toU8(info)
    try toBytes(HmacModule.hmac(Sha256Module.sha256, kU, iU))
    finally
      zero(kU)
      zero(iU)

  private def zero(u: Uint8Array): Unit =
    var i = 0
    while i < u.length do
      u(i) = 0.toShort
      i += 1

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
