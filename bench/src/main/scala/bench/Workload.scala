package bench

import com.google.protobuf.ByteString
import metadatamessenger.store.v1.store as pb

/** The ONE workload definition both simulations drive, so the Rust and Scala runs differ in what
  * is being measured and not in what is being asked of them.
  *
  * ==What this workload is designed to stress==
  *
  * `ObliviousStore` scans EVERY slot on every operation, with the same conditional-assignment work
  * per slot regardless of where (or whether) the token matches. At the default capacity of 4096
  * that is 4096 × (32 + 256 + 1) bytes ≈ 1.2 MB of branchless byte work per single-entry call, so
  * throughput here is dominated by that scan, not by the network front. Capacity is therefore the
  * interesting independent variable, and `batchSize` multiplies the per-call cost linearly.
  *
  * The write/read pairing matters too: reads are single-use and free the slot they consume, so a
  * run that only writes fills the store and then silently no-ops (`write` returns false and the
  * dev front drops it), which would measure a full-store scan rather than a working one. Each
  * virtual user therefore writes a frame and reads it straight back, keeping occupancy bounded.
  */
object Workload:

  val FrameLen: Int = 256
  val TokenLen: Int = 32

  /** Distinct per virtual user AND per iteration, so no two calls contend for one token — a shared
    * token would make every read after the first a miss, quietly turning a hit benchmark into a
    * miss benchmark. Note both still cost a full scan; the point is to measure the intended one. */
  def token(userId: Long, iteration: Long): Array[Byte] =
    val t = new Array[Byte](TokenLen)
    var x = userId * 0x9e3779b97f4a7c15L ^ (iteration + 1) * 0xbf58476d1ce4e5b9L
    var i = 0
    while i < TokenLen do
      x ^= x >>> 30; x *= 0xbf58476d1ce4e5b9L
      x ^= x >>> 27
      t(i) = (x >>> 24).toByte
      i += 1
    t

  /** A frame whose bytes span the full 0..255 range — a store that mishandled the high bit would
    * otherwise pass the benchmark while corrupting data (the port's unit tests pin this too). */
  val frame: Array[Byte] = Array.tabulate(FrameLen)(i => (i & 0xff).toByte)

  def writeRequest(roundId: Long, tokens: Seq[Array[Byte]]): pb.WriteBatchRequest =
    pb.WriteBatchRequest(
      roundId = roundId,
      batchSize = tokens.size,
      entries = tokens.map(t =>
        pb.WriteEntry(writeToken = ByteString.copyFrom(t), frame = ByteString.copyFrom(frame))
      )
    )

  def readRequest(roundId: Long, tokens: Seq[Array[Byte]]): pb.ReadBatchRequest =
    pb.ReadBatchRequest(
      roundId = roundId,
      batchSize = tokens.size,
      entries = tokens.map(t => pb.ReadEntry(retrievalToken = ByteString.copyFrom(t)))
    )

  /** The found tag of the LAST result in a read response, or -1 if there are none.
    *
    * Checked by both simulations because a miss and a hit are the same SIZE on the wire — the
    * `sealed_result` blob is 257 bytes either way, by design — so nothing about the response
    * length distinguishes "read the frame back" from "scanned the whole store and found nothing".
    * Without this the harness would happily report a throughput number for a run that never hit:
    * a capacity misconfiguration, a batch large enough to overflow the store (the dev front drops
    * silently when full), or a regression in the store itself all produce exactly that.
    */
  def foundTag(r: pb.ReadBatchResponse): Int =
    r.results.lastOption match
      case Some(res) if res.sealedResult.size > 0 =>
        res.sealedResult.byteAt(res.sealedResult.size - 1) & 0xff
      case _ => -1

  /** Wraps a serialized protobuf message in the gRPC length-prefixed framing: one compression byte
    * (0 = uncompressed) then a big-endian uint32 length. Used by the HTTP/1.1 simulation, which has
    * to do by hand what the gRPC client does for the h2 one. */
  def grpcFrame(message: Array[Byte]): Array[Byte] =
    val out = new Array[Byte](5 + message.length)
    out(0) = 0
    out(1) = (message.length >>> 24).toByte
    out(2) = (message.length >>> 16).toByte
    out(3) = (message.length >>> 8).toByte
    out(4) = message.length.toByte
    System.arraycopy(message, 0, out, 5, message.length)
    out
