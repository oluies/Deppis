package random

import scala.scalajs.js
import scala.scalajs.js.annotation.JSGlobal
import scala.scalajs.js.typedarray.Uint8Array

/** Cryptographically-strong randomness (Scala.js) via Web Crypto `crypto.getRandomValues` — a
  * vetted platform primitive (NOT hand-rolled, Constitution I), available **synchronously** in both
  * Node (19+) and browsers. The JVM platform provides the same `bytes` via `SecureRandom`. */
@js.native
@JSGlobal("crypto")
private object WebCrypto extends js.Object:
  def getRandomValues(array: Uint8Array): Uint8Array = js.native

object Rand:
  def bytes(n: Int): Array[Byte] =
    val u = new Uint8Array(n)
    WebCrypto.getRandomValues(u)
    val out = new Array[Byte](n)
    var i = 0
    while i < n do
      out(i) = u(i).toByte
      i += 1
    out
