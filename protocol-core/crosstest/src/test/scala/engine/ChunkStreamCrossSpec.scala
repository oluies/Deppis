package engine

import org.scalatest.funsuite.AnyFunSuite

/** SINGLE-SOURCED cross-platform pin of the Phase 2 control-envelope BYTE LAYOUT (design doc §3.1).
  * Compiled into BOTH the JVM `protocolCore` build and the Scala.js `protocolCoreJS` build via each
  * project's `crosstest/src/test` dir (see build.sbt), so the encoding is asserted ONCE and holds
  * identically on both platforms — the two engines must agree byte-for-byte or a rekey between a JVM
  * and a JS peer would fail to reassemble.
  *
  * The vectors are fixed hex, not recomputed from the implementation, so a change to the layout
  * breaks this test loudly rather than silently drifting the two platforms apart. `ChunkStream` is
  * pure (no crypto, no platform primitives), so the fixed vectors are exact on both. */
class ChunkStreamCrossSpec extends AnyFunSuite:
  import ChunkStream.*

  // Mask to unsigned before formatting: Scala.js `"%02x".format(negativeByte)` sign-extends to
  // "ffffffXX" (the JVM Formatter does not), so mask explicitly for cross-platform-stable hex.
  private def toHex(a: Array[Byte]): String = a.map(b => "%02x".format(b & 0xff)).mkString
  private def hex(s: String): Array[Byte] =
    s.grouped(2).map(h => Integer.parseInt(h, 16).toByte).toArray

  test("the padded-payload budget is identical on both platforms"):
    // Derived from DoubleRatchet.InnerSize (172) - ArqFrame.HeaderBytes (16) = 156, minus the
    // 11-byte KEM_CHUNK header = 145 data bytes/chunk. Pinned so a drift on either platform fails.
    assert(DoubleRatchet.InnerSize == 172)
    assert(ArqFrame.PayloadBytes == 156)
    assert(EnvelopeBytes == 156)
    assert(ChunkHeaderBytes == 11)
    assert(ChunkCapacity == 145)
    assert(ConfirmTagBytes == 32)
    assert(MaxChunkCount == 32)

  test("KEM_CHUNK byte layout is pinned: type|epoch(4 BE)|role|part|idx|count|len(2 BE)|data|pad"):
    val data = Array.tabulate[Byte](5)(i => (0xa0 + i).toByte) // a0 a1 a2 a3 a4
    val enc = encode(Envelope.KemChunk(0x01020304, BuddyRole.Initiator, Part.Pub, 0, 1, data))
    val expected =
      "01" + // type = KEM_CHUNK
        "01020304" + // epoch, big-endian
        "01" + // role = Initiator
        "01" + // part = PUB
        "00" + // idx
        "01" + // count
        "0005" + // dataLen, big-endian
        "a0a1a2a3a4" + // data
        "00" * (156 - 11 - 5) // zero pad to the full padded-payload width
    assert(toHex(enc) == expected)
    assert(enc.length == 156)
    // ...and it decodes back to the same envelope on this platform.
    decode(hex(expected)) match
      case Right(c: Envelope.KemChunk) =>
        assert(c.epoch == 0x01020304 && c.role == BuddyRole.Initiator && c.part == Part.Pub)
        assert(c.idx == 0 && c.count == 1 && toHex(c.data) == "a0a1a2a3a4")
      case other => fail(s"KEM_CHUNK vector must decode: $other")

  test("KEM_CHUNK: responder + CT part + a full-capacity middle chunk are pinned"):
    val data = Array.fill[Byte](ChunkCapacity)(0x5a.toByte)
    val enc = encode(Envelope.KemChunk(7, BuddyRole.Responder, Part.Ct, 3, 8, data))
    val expected =
      "01" + // type = KEM_CHUNK (the TYPE tag; the role is a separate field below)
        "00000007" + // epoch
        "02" + // role = Responder
        "02" + // part = CT
        "03" + // idx
        "08" + // count
        "0091" + // dataLen = 145 = ChunkCapacity
        "5a" * 145 // a full-capacity chunk exactly fills the envelope — no pad
    assert(toHex(enc) == expected)
    assert(enc.length == 156)

  test("KEM_CONFIRM byte layout is pinned: type|epoch(4 BE)|role|tag(32)|pad"):
    val tag = Array.tabulate[Byte](32)(i => i.toByte) // 00 01 .. 1f
    val enc = encode(Envelope.KemConfirm(0x000000ff, BuddyRole.Responder, tag))
    val expected =
      "02" + "000000ff" + "02" +
        (0 until 32).map(i => "%02x".format(i)).mkString +
        "00" * (156 - 6 - 32)
    assert(toHex(enc) == expected)
    decode(hex(expected)) match
      case Right(c: Envelope.KemConfirm) =>
        assert(
          c.epoch == 0xff && c.role == BuddyRole.Responder && toHex(c.tag).startsWith("000102")
        )
      case other => fail(s"KEM_CONFIRM vector must decode: $other")

  test("EPOCH_COMMIT byte layout is pinned: type|epoch(4 BE)|role|pad"):
    val enc = encode(Envelope.EpochCommit(0x7fffffff, BuddyRole.Initiator))
    val expected = "03" + "7fffffff" + "01" + "00" * (156 - 6)
    assert(toHex(enc) == expected)
    assert(decode(hex(expected)) == Right(Envelope.EpochCommit(0x7fffffff, BuddyRole.Initiator)))

  test("the chunk splitter's frame counts match the doc's rekey budget on both platforms"):
    // Doc §3.1: hybrid pubkey 1216 B ⇒ 9 chunks, hybrid ciphertext 1120 B ⇒ 8 chunks.
    def count(n: Int, p: Part): Int =
      chunk(1, BuddyRole.Initiator, p, new Array[Byte](n)).toOption.get.size
    assert(count(1216, Part.Pub) == 9)
    assert(count(1120, Part.Ct) == 8)

  test("a cross-platform reassembly of a pinned object yields identical bytes"):
    val obj = Array.tabulate[Byte](300)(i => (i * 7 + 3).toByte)
    val cs = chunk(2, BuddyRole.Initiator, Part.Pub, obj).toOption.get
    assert(cs.size == 3) // 145 + 145 + 10
    val ra = ChunkReassembler()
    // Reversed + duplicated: reassembly must be order- and duplicate-insensitive on both platforms.
    val done = (cs.reverse ++ cs).flatMap { p =>
      ra.feed(decode(p).toOption.get.asInstanceOf[Envelope.KemChunk]).toOption.get
    }
    assert(done.size == 1)
    assert(toHex(done.head.bytes) == toHex(obj))

  test("fail-closed decoding is identical on both platforms"):
    val good = encode(Envelope.EpochCommit(1, BuddyRole.Initiator))
    assert(decode(good.dropRight(1)) == Left(ChunkError.BadLength))
    assert(decode(good.updated(0, 0x09.toByte)) == Left(ChunkError.UnknownType))
    assert(decode(good.updated(5, 0x00.toByte)) == Left(ChunkError.BadRole))
    // idx >= count and an absurd count, on a real chunk vector.
    val c = encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 1, Array[Byte](1, 2)))
    assert(decode(c.updated(7, 5.toByte)) == Left(ChunkError.BadIndex))
    assert(decode(c.updated(8, 0.toByte)) == Left(ChunkError.BadCount))
    assert(decode(c.updated(8, 0xff.toByte)) == Left(ChunkError.BadCount))
    // A declared data length past the envelope must never be trusted.
    assert(
      decode(c.updated(9, 0xff.toByte).updated(10, 0xff.toByte)) ==
        Left(ChunkError.BadDataLength)
    )
