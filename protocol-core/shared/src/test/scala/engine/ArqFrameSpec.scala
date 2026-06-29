package engine

import org.scalatest.funsuite.AnyFunSuite

/** Unit tests for the stop-and-wait ARQ inner-block framing + the de-duplication decision. The
  * end-to-end retransmit/ack behaviour only becomes exercisable once round-derived addressing lands
  * (Stage 2), so the dedup decision — the core behavioural addition of Stage 1 — is pinned here. */
class ArqFrameSpec extends AnyFunSuite:

  // A full-width padded payload (the only width `encode` accepts).
  private def payload(fill: Int): Array[Byte] =
    Array.tabulate[Byte](ArqFrame.PayloadBytes)(i => (i * 3 + fill).toByte)

  test("encode/decode round-trips ackSeq, msgSeq, and the payload"):
    val p = payload(1)
    val inner = ArqFrame.encode(ackSeq = 7L, msgSeq = 42L, p)
    assert(inner.length == ArqFrame.HeaderBytes + ArqFrame.PayloadBytes)
    assert(ArqFrame.ackSeqOf(inner) == 7L)
    assert(ArqFrame.msgSeqOf(inner) == 42L)
    assert(ArqFrame.payloadOf(inner).sameElements(p))

  test("encode rejects a wrong-width payload (invariant enforced at the API boundary)"):
    assertThrows[IllegalArgumentException](ArqFrame.encode(0L, 0L, Array.emptyByteArray))
    assertThrows[IllegalArgumentException](
      ArqFrame.encode(0L, 0L, new Array[Byte](ArqFrame.PayloadBytes - 1))
    )

  test("8-byte fields survive large/edge values (BE, unsigned reassembly)"):
    val p = payload(2)
    for v <- Seq(0L, 1L, 255L, 256L, 65535L, Long.MaxValue, ArqFrame.NoSeq) do
      val inner = ArqFrame.encode(v, v, p)
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
