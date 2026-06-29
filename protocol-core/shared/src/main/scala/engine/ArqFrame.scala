package engine

/** Stop-and-wait ARQ inner-block framing (retry-safe-addressing.md). The DH ratchet seals
  * `[ackSeq(8 BE)][msgSeq(8 BE)][padded payload]`, so every frame carries the sender's highest-received
  * sequence (the ack, so the peer can stop retransmitting) and this message's sequence (so the receiver
  * can de-duplicate a retransmit). It rides INSIDE the ratchet inner block, so the store never sees it.
  *
  * Pure and cross-platform; the sequence/dedup decision is unit-tested in `ArqFrameSpec` (the
  * end-to-end retransmit/ack behaviour only becomes exercisable once round-derived addressing lands in
  * Stage 2, so the decision is tested directly here). */
object ArqFrame:
  /** Bytes the ack+seq header consumes from the ratchet inner block. */
  val HeaderBytes: Int = 16

  /** Sentinel `msgSeq` for a frame carrying no new message (an ack-only frame — Stage 2). */
  val NoSeq: Long = -1L

  /** `[ackSeq][msgSeq][paddedPayload]`. `paddedPayload` is already the message region's width. */
  def encode(ackSeq: Long, msgSeq: Long, paddedPayload: Array[Byte]): Array[Byte] =
    enc8(ackSeq) ++ enc8(msgSeq) ++ paddedPayload

  def ackSeqOf(inner: Array[Byte]): Long = dec8(inner, 0)
  def msgSeqOf(inner: Array[Byte]): Long = dec8(inner, 8)
  def payloadOf(inner: Array[Byte]): Array[Byte] = inner.drop(HeaderBytes)

  /** True iff `msgSeq` is a real sequence strictly beyond the highest already received — i.e. a NEW
    * message to deliver. A retransmit re-presents an already-seen seq (`≤ highRecv`); an ack-only frame
    * carries [[NoSeq]]. Both are non-new ⇒ not delivered. */
  def isNewMessage(msgSeq: Long, highRecv: Long): Boolean = msgSeq != NoSeq && msgSeq > highRecv

  private def enc8(v: Long): Array[Byte] =
    val out = new Array[Byte](8)
    var i = 0
    while i < 8 do { out(i) = ((v >>> (56 - 8 * i)) & 0xff).toByte; i += 1 }
    out

  private def dec8(b: Array[Byte], off: Int): Long =
    var v = 0L
    var i = 0
    while i < 8 do { v = (v << 8) | (b(off + i) & 0xffL); i += 1 }
    v
