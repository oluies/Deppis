package engine

import org.scalatest.funsuite.AnyFunSuite

/** Unit tests for the stop-and-wait ARQ inner-block framing + the de-duplication decision. The
  * end-to-end retransmit/ack behaviour only becomes exercisable once round-derived addressing lands
  * (Stage 2), so the dedup decision — the core behavioural addition of Stage 1 — is pinned here. */
class ArqFrameSpec extends AnyFunSuite:

  test("encode/decode round-trips ackSeq, msgSeq, and the payload"):
    val payload = Array.tabulate[Byte](40)(i => (i * 3 + 1).toByte)
    val inner = ArqFrame.encode(ackSeq = 7L, msgSeq = 42L, payload)
    assert(inner.length == ArqFrame.HeaderBytes + payload.length)
    assert(ArqFrame.ackSeqOf(inner) == 7L)
    assert(ArqFrame.msgSeqOf(inner) == 42L)
    assert(ArqFrame.payloadOf(inner).sameElements(payload))

  test("8-byte fields survive large/edge values (BE, unsigned reassembly)"):
    for v <- Seq(0L, 1L, 255L, 256L, 65535L, Long.MaxValue, ArqFrame.NoSeq) do
      val inner = ArqFrame.encode(v, v, Array.emptyByteArray)
      assert(ArqFrame.ackSeqOf(inner) == v, s"ack $v")
      assert(ArqFrame.msgSeqOf(inner) == v, s"seq $v")

  test("isNewMessage: a strictly-higher real sequence is new"):
    assert(ArqFrame.isNewMessage(msgSeq = 0L, highRecv = ArqFrame.NoSeq)) // first message
    assert(ArqFrame.isNewMessage(msgSeq = 5L, highRecv = 4L))

  test(
    "isNewMessage: a re-presented (≤ highRecv) sequence is NOT new — a retransmit must not re-deliver"
  ):
    assert(!ArqFrame.isNewMessage(msgSeq = 4L, highRecv = 4L)) // exact dup
    assert(!ArqFrame.isNewMessage(msgSeq = 2L, highRecv = 4L)) // older dup

  test("isNewMessage: an ack-only frame (NoSeq) is NOT new — no delivery"):
    assert(!ArqFrame.isNewMessage(msgSeq = ArqFrame.NoSeq, highRecv = ArqFrame.NoSeq))
    assert(!ArqFrame.isNewMessage(msgSeq = ArqFrame.NoSeq, highRecv = 9L))
