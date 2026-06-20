package engine

import scala.scalajs.js.typedarray.Uint8Array

/** Single home for the `Array[Byte]` ↔ `Uint8Array` marshalling used across the JS engine bridge
  * (EngineJs, JsRoundTransport, tests) — so the byte-conversion logic exists once, not copied. */
object Uint8:

  def toJs(a: Array[Byte]): Uint8Array =
    val u = new Uint8Array(a.length)
    var i = 0
    while i < a.length do
      u(i) = (a(i) & 0xff).toShort
      i += 1
    u

  def toBytes(u: Uint8Array): Array[Byte] =
    val out = new Array[Byte](u.length)
    var i = 0
    while i < u.length do
      out(i) = u(i).toByte
      i += 1
    out
