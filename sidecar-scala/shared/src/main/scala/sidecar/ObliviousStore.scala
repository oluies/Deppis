package sidecar

/** A Scala port of the Rust sidecar's oblivious PONG store (`oblivious-sidecar/src/store.rs`),
  * written to be measured against it — see `bench/README.md`.
  *
  * ==This carries NO privacy claim==
  *
  * The Rust original uses the `subtle` crate, whose `ConditionallySelectable`/`ConstantTimeEq`
  * carry the compiler barriers that make "constant time" a property the toolchain must preserve.
  * Neither the JVM nor Scala Native offers an equivalent, so the conditional assignments below are
  * hand-written integer arithmetic and NOTHING stops HotSpot's or LLVM's optimiser from
  * reintroducing a branch. Treat this as "does the same amount of work", which is what a
  * throughput benchmark needs, and NOT as "leaks nothing through timing", which it does not
  * establish. The Rust sidecar remains the only implementation the metadata-privacy argument rests
  * on (Constitution I, IV).
  *
  * ==Why it is written this way==
  *
  * Fidelity to what is being measured. The slot table is three FLAT arrays rather than an array of
  * slot objects, because the Rust side is a `Vec<Slot>` — one contiguous allocation with no
  * per-slot header or pointer hop. An `Array[Slot]` of objects would have measured the JVM's
  * object layout instead of the scan, and would have flattered neither runtime honestly.
  *
  * The invariants ported from the original: every `write` and `read` touches EVERY slot with the
  * same operations, so the access pattern depends only on the public capacity; reads are
  * single-use, clearing and zeroizing the matched slot; and a read always yields a full
  * `FrameLen` result, carrier zeros on a miss, so hit-vs-miss is not visible in the result shape.
  */
object ObliviousStore:
  val TokenLen: Int = 32
  val FrameLen: Int = 256

  /** 0xff if the low byte of `x` is zero, else 0x00 — branchlessly.
    *
    * For `v` in 0..255: `v == 0` gives `-1 >>> 8 = 0x00ffffff`, and any `v > 0` gives
    * `(v - 1) >>> 8 = 0`. Masking to a byte then yields the all-ones / all-zeros selector the
    * conditional assignments below use.
    */
  private inline def ctIsZero(x: Int): Int = (((x & 0xff) - 1) >>> 8) & 0xff

/** Fixed-capacity store. Not thread-safe: the gRPC front serializes access, mirroring the
  * `Mutex<ObliviousStore>` the Rust front holds. */
final class ObliviousStore(val capacity: Int):
  import ObliviousStore.*

  require(capacity > 0, "capacity must be positive")

  private val occupied = new Array[Byte](capacity)
  private val tokens = new Array[Byte](capacity * TokenLen)
  private val frames = new Array[Byte](capacity * FrameLen)

  /** Place `(token, frame)` in the first free slot, scanning all of them. Returns false iff the
    * store was full — capacity is public, so that is the only data-independent signal. */
  def write(token: Array[Byte], frame: Array[Byte]): Boolean =
    require(token.length == TokenLen && frame.length == FrameLen)
    var placed = 0
    var i = 0
    while i < capacity do
      val isFree = ctIsZero(occupied(i).toInt)
      val take = isFree & ~placed & 0xff // first free slot only
      occupied(i) = ((occupied(i) & ~take) | (1 & take)).toByte
      val tb = i * TokenLen
      var j = 0
      while j < TokenLen do
        tokens(tb + j) = ((tokens(tb + j) & ~take) | (token(j) & take)).toByte
        j += 1
      val fb = i * FrameLen
      j = 0
      while j < FrameLen do
        frames(fb + j) = ((frames(fb + j) & ~take) | (frame(j) & take)).toByte
        j += 1
      placed |= take
      i += 1
    placed != 0

  /** Single-use read by token, writing the frame (or carrier zeros) into `out`. Returns whether
    * the token was found; that flag becomes the `sealed_result` found tag in the gRPC contract.
    * The matched slot is cleared and zeroized, so a token never yields a frame twice. */
  def readSealed(token: Array[Byte], out: Array[Byte]): Boolean =
    require(token.length == TokenLen && out.length >= FrameLen)
    java.util.Arrays.fill(out, 0, FrameLen, 0.toByte)
    var found = 0
    var i = 0
    while i < capacity do
      val occ = ctIsZero(occupied(i).toInt ^ 1)
      val tb = i * TokenLen
      var diff = 0
      var j = 0
      while j < TokenLen do
        diff |= (tokens(tb + j) ^ token(j)) & 0xff
        j += 1
      val m = occ & ctIsZero(diff)
      val fb = i * FrameLen
      j = 0
      while j < FrameLen do
        val f = frames(fb + j) & 0xff
        out(j) = ((out(j) & ~m) | (f & m)).toByte // capture the frame first
        frames(fb + j) = (f & ~m).toByte // then erase it on consume
        j += 1
      j = 0
      while j < TokenLen do
        tokens(tb + j) = (tokens(tb + j) & ~m).toByte
        j += 1
      occupied(i) = (occupied(i) & ~m).toByte // mark free (non-recurrent)
      found |= m
      i += 1
    found != 0
