package sidecar

import scala.scalanative.runtime.{ByteArray, fromRawPtr}
import scala.scalanative.unsafe.Ptr

/** Scala Native side of the bounds-check experiment.
  *
  * This is a deliberately minimal variable change. It is NOT a reimplementation of the store: it
  * scans the very same `ObliviousStore` object, over the very same three flat arrays, with the same
  * branchless conditional-assignment arithmetic in the same order. The only difference is that
  * every access goes through a raw `Ptr[Byte]` obtained with `atRawUnsafe`, so the array bounds
  * checks Scala Native emits — confirmed present even under `releaseFast`, where an out-of-range
  * read still throws `ArrayIndexOutOfBoundsException` — are absent.
  *
  * If the safe and unsafe numbers are close, bounds checks are not what makes the Native scan slow
  * and the cause is elsewhere in codegen. If the unsafe one approaches Rust, they are.
  *
  * NOT FOR PRODUCTION USE. Skipping bounds checks on indices derived from request data is exactly
  * the shape of a memory-safety bug; this exists to attribute a benchmark result and nothing else.
  * The server path uses the safe [[ObliviousStore]].
  */
object UnsafeScan:
  import ObliviousStore.{FrameLen, TokenLen}

  val available: Boolean = true

  private inline def ptr(a: Array[Byte]): Ptr[Byte] =
    fromRawPtr[Byte](a.asInstanceOf[ByteArray].atRawUnsafe(0))

  private inline def ctIsZero(x: Int): Int = (((x & 0xff) - 1) >>> 8) & 0xff

  object Ops extends ScanBench.RoundOps:

    def write(store: ObliviousStore, token: Array[Byte], frame: Array[Byte]): Boolean =
      val occupied = ptr(store.occupied)
      val tokens = ptr(store.tokens)
      val frames = ptr(store.frames)
      val tok = ptr(token)
      val frm = ptr(frame)
      val capacity = store.capacity
      var placed = 0
      var i = 0
      while i < capacity do
        val isFree = ctIsZero(occupied(i).toInt)
        val take = isFree & ~placed & 0xff
        occupied(i) = ((occupied(i) & ~take) | (1 & take)).toByte
        val tb = i * TokenLen
        var j = 0
        while j < TokenLen do
          tokens(tb + j) = ((tokens(tb + j) & ~take) | (tok(j) & take)).toByte
          j += 1
        val fb = i * FrameLen
        j = 0
        while j < FrameLen do
          frames(fb + j) = ((frames(fb + j) & ~take) | (frm(j) & take)).toByte
          j += 1
        placed |= take
        i += 1
      placed != 0

    def read(store: ObliviousStore, token: Array[Byte], out: Array[Byte]): Boolean =
      val occupied = ptr(store.occupied)
      val tokens = ptr(store.tokens)
      val frames = ptr(store.frames)
      val tok = ptr(token)
      val o = ptr(out)
      val capacity = store.capacity
      var k = 0
      while k < FrameLen do
        o(k) = 0.toByte
        k += 1
      var found = 0
      var i = 0
      while i < capacity do
        val occ = ctIsZero(occupied(i).toInt ^ 1)
        val tb = i * TokenLen
        var diff = 0
        var j = 0
        while j < TokenLen do
          diff |= (tokens(tb + j) ^ tok(j)) & 0xff
          j += 1
        val m = occ & ctIsZero(diff)
        val fb = i * FrameLen
        j = 0
        while j < FrameLen do
          val f = frames(fb + j) & 0xff
          o(j) = ((o(j) & ~m) | (f & m)).toByte
          frames(fb + j) = (f & ~m).toByte
          j += 1
        j = 0
        while j < TokenLen do
          tokens(tb + j) = (tokens(tb + j) & ~m).toByte
          j += 1
        occupied(i) = (occupied(i) & ~m).toByte
        found |= m
        i += 1
      found != 0
