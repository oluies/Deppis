package engine

import frame.Frame
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks

import java.nio.charset.StandardCharsets.UTF_8

/** Tests for the Phase 2 chunked control sub-stream (design doc §3.1 / §7 Phase 2). Three concerns,
  * in order: (1) the envelope FITS the real ARQ payload budget and cannot be confused with user
  * content — asserted against the actual `ArqFrame`/`Frame` constants, never a copied literal, so a
  * future change to the inner block breaks these tests rather than the wire; (2) chunk→reassemble is
  * a faithful, exactly-once round trip under duplication and reordering (ARQ already dedups/orders,
  * so this is the defensive layer on top — doc §3.1); (3) every attacker-influenceable field fails
  * closed. Property tests mirror `ArqStressSpec`/`DoubleRatchetModelSpec` style: random scripts, a
  * reference oracle, ScalaCheck shrinking on failure.
  *
  * The byte layout itself is pinned cross-platform by `ChunkStreamCrossSpec` (crosstest/). */
class ChunkStreamSpec extends AnyFunSuite with ScalaCheckPropertyChecks:
  import ChunkStream.*

  private def bytes(n: Int, seed: Int = 0): Array[Byte] =
    Array.tabulate[Byte](n)(i => (i * 31 + seed * 7 + 1).toByte)

  private def chunksOf(b: Array[Byte], epoch: Int = 1, part: Part = Part.Pub): Vector[Array[Byte]] =
    chunk(epoch, BuddyRole.Initiator, part, b).toOption.get

  private def decodeChunk(padded: Array[Byte]): Envelope.KemChunk =
    decode(padded).toOption.get.asInstanceOf[Envelope.KemChunk]

  // ---------------------------------------------------------------- budget & frame-format safety

  test("the envelope fits the REAL ARQ payload budget exactly (no frame-size impact)"):
    // Single-sourced from the transport constant: an envelope IS a full-width ARQ padded payload,
    // so `ArqFrame.encode` accepts it and the sealed inner block — hence the 256-B wire frame — is
    // unchanged in size. Verified against the code, not the doc's prose.
    assert(EnvelopeBytes == ArqFrame.PayloadBytes)
    assert(ChunkCapacity == ArqFrame.PayloadBytes - ChunkHeaderBytes)
    assert(ChunkHeaderBytes + ChunkCapacity <= ArqFrame.PayloadBytes)
    val env = encode(Envelope.EpochCommit(0, BuddyRole.Initiator))
    assert(env.length == ArqFrame.PayloadBytes)
    // The real proof that nothing about the frame changes: ARQ accepts it at its exact width.
    val inner = ArqFrame.encode(0L, 0L, env)
    assert(inner.length == DoubleRatchet.InnerSize)

  test("every encoded envelope type is exactly the full padded-payload width"):
    val all = Seq(
      Envelope.KemChunk(3, BuddyRole.Initiator, Part.Pub, 0, 1, bytes(10)),
      Envelope.KemConfirm(3, BuddyRole.Responder, bytes(ConfirmTagBytes)),
      Envelope.EpochCommit(3, BuddyRole.Initiator)
    )
    all.foreach(e => assert(encode(e).length == EnvelopeBytes, s"$e"))

  test("the doc's ~19-frame rekey budget holds at the real chunk capacity"):
    // Doc §3.1: hybrid pubkey 1216 B ⇒ 9 frames, ciphertext 1120 B ⇒ 8, +2 confirms ⇒ ~19.
    assert(chunksOf(bytes(1216)).size == 9, "hybrid pubkey ⇒ 9 chunks")
    assert(chunksOf(bytes(1120), part = Part.Ct).size == 8, "hybrid ciphertext ⇒ 8 chunks")
    assert(9 + 8 + 2 + 1 <= 20, "full rekey stays within the doc's ~19-frame budget (+1 commit)")

  test("byte 0 discriminates control from Frame.pad'ed user content, both ways"):
    // User content in this region is `Frame.pad(msg, PayloadBytes)`; its byte 0 is the BE-high byte
    // of a length <= 154, i.e. always 0. Control tags are nonzero. Neither can spoof the other.
    val content = Frame.pad("hello".getBytes(UTF_8), ArqFrame.PayloadBytes).toOption.get
    assert(!isControl(content))
    assert(decode(content).isLeft, "content must not decode as a control envelope")
    // Maximal-length content: still byte-0 zero (the invariant `maxPayload(156) < 256` is what
    // makes this sound, and `ChunkStream` requires it at init).
    val maxContent =
      Frame.pad(bytes(Frame.maxPayload(ArqFrame.PayloadBytes)), ArqFrame.PayloadBytes).toOption.get
    assert(!isControl(maxContent) && decode(maxContent).isLeft)
    Seq(
      Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 1, bytes(5)),
      Envelope.KemConfirm(1, BuddyRole.Initiator, bytes(ConfirmTagBytes)),
      Envelope.EpochCommit(1, BuddyRole.Initiator)
    ).foreach { e =>
      val enc = encode(e)
      assert(isControl(enc), s"$e must be recognized as control")
      // And it must NOT decode as user content (Frame.unpad would read an absurd length).
      assert(Frame.unpad(enc, ArqFrame.PayloadBytes).isLeft, s"$e must not unpad as content")
    }

  // ----------------------------------------------------------------------------- encode/decode

  test("encode/decode round-trips every envelope type, including the empty-object chunk"):
    val tag = bytes(ConfirmTagBytes, seed = 5)
    for
      role <- Seq(BuddyRole.Initiator, BuddyRole.Responder)
      part <- Seq(Part.Pub, Part.Ct)
    do
      val c = Envelope.KemChunk(0x01020304, role, part, 2, 3, bytes(ChunkCapacity, 2))
      decode(encode(c)) match
        case Right(g: Envelope.KemChunk) =>
          assert(g.epoch == 0x01020304 && g.role == role && g.part == part)
          assert(g.idx == 2 && g.count == 3 && g.data.sameElements(bytes(ChunkCapacity, 2)))
        case other => fail(s"KEM_CHUNK round-trip: $other")
      decode(encode(Envelope.KemConfirm(7, role, tag))) match
        case Right(g: Envelope.KemConfirm) =>
          assert(g.epoch == 7 && g.role == role && g.tag.sameElements(tag))
        case other => fail(s"KEM_CONFIRM round-trip: $other")
      assert(
        decode(encode(Envelope.EpochCommit(9, role))) == Right(Envelope.EpochCommit(9, role))
      )
    // The empty object: exactly one chunk, zero data (canonical form).
    val empty = chunksOf(Array.emptyByteArray)
    assert(empty.size == 1)
    val e0 = decodeChunk(empty.head)
    assert(e0.idx == 0 && e0.count == 1 && e0.data.isEmpty)

  test("epoch survives the full non-negative Int range (BE, unsigned reassembly)"):
    for e <- Seq(0, 1, 255, 256, 65535, 0x00ffffff, Int.MaxValue) do
      assert(
        decode(encode(Envelope.EpochCommit(e, BuddyRole.Initiator))) ==
          Right(Envelope.EpochCommit(e, BuddyRole.Initiator))
      )

  test("the decoder returns COPIES, never aliases into the caller's buffer"):
    val enc = encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 1, bytes(20)))
    val got = decodeChunk(enc)
    java.util.Arrays.fill(enc, 0.toByte) // scribble the source
    assert(got.data.sameElements(bytes(20)), "decoded data must not alias the input")

  // --------------------------------------------------------------------- chunking & reassembly

  test("chunk assigns canonical idx/count: all full but the last"):
    val b = bytes(ChunkCapacity * 2 + 3)
    val cs = chunksOf(b).map(decodeChunk)
    assert(cs.size == 3)
    assert(cs.map(_.idx) == Vector(0, 1, 2))
    assert(cs.forall(_.count == 3))
    assert(cs.take(2).forall(_.data.length == ChunkCapacity))
    assert(cs.last.data.length == 3)

  test("round-trip: chunk -> shuffle + duplicate -> reassemble == original, EXACTLY once"):
    val original = bytes(1216) // the hybrid pubkey size — the real Phase 3 payload
    val cs = chunksOf(original)
    val ra = ChunkReassembler()
    // Every chunk twice, shuffled: ARQ dedups upstream, but the reassembler is defensive.
    val script = scala.util.Random(42).shuffle(cs ++ cs)
    val completions = script.flatMap { padded =>
      ra.feed(decodeChunk(padded)) match
        case Right(done) => done
        case Left(err) => fail(s"a genuine (possibly duplicate) chunk was rejected: $err")
    }
    assert(completions.size == 1, "exactly-once: one completion despite duplicates")
    assert(completions.head.bytes.sameElements(original))
    assert(completions.head.epoch == 1 && completions.head.part == Part.Pub)
    // Replaying the whole transfer after completion yields nothing more (late-duplicate window).
    assert(cs.flatMap(p => ra.feed(decodeChunk(p)).toOption.flatten).isEmpty)

  test("transfers keyed by (epoch, part) are independent and do not cross-contaminate"):
    val pub = bytes(1216, 1)
    val ct = bytes(1120, 2)
    val nextEpochPub = bytes(300, 3)
    val all =
      chunk(5, BuddyRole.Initiator, Part.Pub, pub).toOption.get.map((_, "a")) ++
        chunk(5, BuddyRole.Responder, Part.Ct, ct).toOption.get.map((_, "b")) ++
        chunk(6, BuddyRole.Initiator, Part.Pub, nextEpochPub).toOption.get.map((_, "c"))
    val ra = ChunkReassembler()
    val done = scala.util.Random(7).shuffle(all).flatMap { case (p, _) =>
      ra.feed(decodeChunk(p)).toOption.get
    }
    assert(done.size == 3)
    val byKey = done.map(c => (c.epoch, c.role, c.part) -> c.bytes).toMap
    assert(byKey((5, BuddyRole.Initiator, Part.Pub)).sameElements(pub))
    assert(byKey((5, BuddyRole.Responder, Part.Ct)).sameElements(ct))
    assert(byKey((6, BuddyRole.Initiator, Part.Pub)).sameElements(nextEpochPub))

  test("property: any size (0, 1, exact multiples, +/-1) survives shuffle+duplicate reassembly"):
    val genSize: Gen[Int] = Gen.oneOf(
      Gen.const(0),
      Gen.const(1),
      Gen.choose(0, MaxObjectBytes), // arbitrary
      Gen.choose(1, MaxChunkCount).map(_ * ChunkCapacity), // exact multiples
      Gen.choose(1, MaxChunkCount - 1).map(_ * ChunkCapacity + 1), // multiple + 1
      Gen.choose(1, MaxChunkCount).map(_ * ChunkCapacity - 1) // multiple - 1
    )
    forAll(genSize, Gen.choose(0, 3), Gen.choose(0L, Long.MaxValue)) { (n, dupTimes, seed) =>
      whenever(n >= 0 && n <= MaxObjectBytes) {
        val original = bytes(n, seed.toInt & 0x7f)
        val cs = chunksOf(original)
        assert(cs.size == math.max(1, (n + ChunkCapacity - 1) / ChunkCapacity))
        val rnd = scala.util.Random(seed)
        val script = rnd.shuffle(Vector.fill(dupTimes + 1)(cs).flatten)
        val ra = ChunkReassembler()
        val done = script.flatMap(p => ra.feed(decodeChunk(p)).toOption.get)
        assert(done.size == 1, s"exactly-once for n=$n dup=${dupTimes + 1}")
        assert(done.head.bytes.sameElements(original), s"faithful reassembly for n=$n")
      }
    }

  test("property: every encoded chunk is padded-payload-width and strictly decodable"):
    forAll(Gen.choose(0, MaxObjectBytes)) { n =>
      chunksOf(bytes(n)).foreach { p =>
        assert(p.length == ArqFrame.PayloadBytes)
        assert(decode(p).isRight)
        assert(isControl(p))
      }
    }

  test("an incomplete transfer never yields (a missing chunk keeps the object pending)"):
    val cs = chunksOf(bytes(1216))
    val ra = ChunkReassembler()
    val done = cs.drop(1).flatMap(p => ra.feed(decodeChunk(p)).toOption.get) // chunk 0 lost
    assert(done.isEmpty)
    // ARQ retransmits it; the transfer completes on arrival, still exactly once.
    assert(ra.feed(decodeChunk(cs.head)).toOption.get.exists(_.bytes.sameElements(bytes(1216))))

  test("the reassembler does not alias the caller's chunk array"):
    val cs = chunksOf(bytes(200))
    val ra = ChunkReassembler()
    val first = decodeChunk(cs(0))
    ra.feed(first): Unit
    java.util.Arrays.fill(first.data, 0x7f.toByte) // scribble after feeding
    val done = ra.feed(decodeChunk(cs(1))).toOption.get
    assert(done.get.bytes.sameElements(bytes(200)), "stored chunk must be an owned copy")

  // -------------------------------------------------------------------------- fail-closed cases

  private def corrupt(base: Array[Byte])(f: Array[Byte] => Unit): Array[Byte] =
    val c = base.clone(); f(c); c

  test("fail closed: wrong width (truncated or oversize) rejects"):
    val good = encode(Envelope.EpochCommit(1, BuddyRole.Initiator))
    assert(decode(good.dropRight(1)) == Left(ChunkError.BadLength))
    assert(decode(good :+ 0.toByte) == Left(ChunkError.BadLength))
    assert(decode(Array.emptyByteArray) == Left(ChunkError.BadLength))
    // A truncated envelope is also not "control" by the width-checked predicate.
    assert(!isControl(good.dropRight(1)))

  test("fail closed: unknown type tag rejects (no partial trust)"):
    val good = encode(Envelope.EpochCommit(1, BuddyRole.Initiator))
    for t <- Seq(0x04, 0x05, 0x7f, 0x80, 0xfe, 0xff) do
      assert(decode(corrupt(good)(_(0) = t.toByte)) == Left(ChunkError.UnknownType), s"tag $t")

  test("fail closed: a negative epoch (high bit set) rejects rather than wrapping"):
    val good = encode(Envelope.EpochCommit(1, BuddyRole.Initiator))
    assert(decode(corrupt(good)(_(1) = 0x80.toByte)) == Left(ChunkError.BadEpoch))

  test("fail closed: an unknown role or part byte rejects"):
    val commit = encode(Envelope.EpochCommit(1, BuddyRole.Initiator))
    assert(decode(corrupt(commit)(_(5) = 0x00)) == Left(ChunkError.BadRole))
    assert(decode(corrupt(commit)(_(5) = 0x03)) == Left(ChunkError.BadRole))
    val c = encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 1, bytes(4)))
    assert(decode(corrupt(c)(_(6) = 0x00)) == Left(ChunkError.BadPart))
    assert(decode(corrupt(c)(_(6) = 0x09)) == Left(ChunkError.BadPart))

  test("fail closed: idx >= count rejects"):
    val c = encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 1, 2, bytes(4)))
    assert(decode(corrupt(c)(_(7) = 2)) == Left(ChunkError.BadIndex)) // idx == count
    assert(decode(corrupt(c)(_(7) = 9)) == Left(ChunkError.BadIndex)) // idx > count
    // Also rejected at the API boundary (sender-side inputs fail loudly).
    assertThrows[IllegalArgumentException](
      encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 2, 2, bytes(4)))
    )
    // ...and defensively in the reassembler, for a directly-constructed value.
    assert(
      ChunkReassembler().feed(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 5, 2, bytes(4)))
        == Left(ChunkError.BadIndex)
    )

  test("fail closed: count = 0 rejects (no zero-chunk object)"):
    val c = encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 1, bytes(4)))
    assert(decode(corrupt(c)(_(8) = 0)) == Left(ChunkError.BadCount))
    assert(
      ChunkReassembler().feed(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 0, bytes(4)))
        == Left(ChunkError.BadCount)
    )

  test("fail closed: an absurd count is capped (bounded memory vs an attacker-set field)"):
    val c = encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 1, bytes(ChunkCapacity)))
    for n <- Seq(MaxChunkCount + 1, 100, 200, 255) do
      assert(decode(corrupt(c)(_(8) = n.toByte)) == Left(ChunkError.BadCount), s"count $n")
    // The cap is enforced in the reassembler too, so no pending state is ever allocated for it.
    val ra = ChunkReassembler()
    assert(
      ra.feed(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 999, bytes(ChunkCapacity)))
        == Left(ChunkError.BadCount)
    )
    // And the boundary itself is accepted (the cap is >= the doc's 9-chunk budget with headroom).
    assert(MaxChunkCount >= 9, "cap must cover the doc's 9-chunk hybrid pubkey")
    assert(decode(corrupt(c)(_(8) = MaxChunkCount.toByte)).isRight)

  test("fail closed: a declared data length beyond the buffer/capacity rejects"):
    val c = encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 1, bytes(4)))
    // dataLen > ChunkCapacity: would read past the envelope if trusted. It must never be trusted.
    val over = corrupt(c) { a =>
      a(9) = ((ChunkCapacity + 1) >>> 8).toByte; a(10) = ((ChunkCapacity + 1) & 0xff).toByte
    }
    assert(decode(over) == Left(ChunkError.BadDataLength))
    val huge = corrupt(c) { a =>
      a(9) = 0xff.toByte; a(10) = 0xff.toByte
    }
    assert(decode(huge) == Left(ChunkError.BadDataLength))

  test("fail closed: non-canonical chunk sizes reject (a non-last chunk must be full)"):
    // idx 0 of 2 carrying a short payload: offsets would be ambiguous. Reject.
    val short =
      encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(ChunkCapacity)))
    val tampered = corrupt(short) { a =>
      a(9) = 0; a(10) = 5
    } // claim 5 bytes in a non-last chunk
    assert(decode(tampered) == Left(ChunkError.BadDataLength))
    assertThrows[IllegalArgumentException](
      encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(5)))
    )
    // An EMPTY last chunk is only legal as the sole chunk of an empty object.
    assertThrows[IllegalArgumentException](
      encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 1, 2, Array.emptyByteArray))
    )
    assert(
      encode(
        Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 1, Array.emptyByteArray)
      ).length == EnvelopeBytes
    )

  test("fail closed: nonzero padding rejects (the encoding is canonical, not malleable)"):
    // Padding malleability would let an adversary produce many distinct envelopes with identical
    // semantics; the decoder pins one canonical byte string per envelope.
    val c = encode(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 1, bytes(4)))
    assert(decode(corrupt(c)(a => a(EnvelopeBytes - 1) = 1)) == Left(ChunkError.NonZeroPadding))
    assert(decode(corrupt(c)(a => a(ChunkHeaderBytes + 4) = 1)) == Left(ChunkError.NonZeroPadding))
    val confirm = encode(Envelope.KemConfirm(1, BuddyRole.Initiator, bytes(ConfirmTagBytes)))
    assert(
      decode(corrupt(confirm)(a => a(6 + ConfirmTagBytes) = 1)) ==
        Left(ChunkError.NonZeroPadding)
    )
    val commit = encode(Envelope.EpochCommit(1, BuddyRole.Initiator))
    assert(decode(corrupt(commit)(a => a(6) = 1)) == Left(ChunkError.NonZeroPadding))

  test("fail closed: an oversize object is refused by the splitter"):
    assert(
      chunk(1, BuddyRole.Initiator, Part.Pub, bytes(MaxObjectBytes + 1)) ==
        Left(ChunkError.OversizeObject)
    )
    assert(chunk(1, BuddyRole.Initiator, Part.Pub, bytes(MaxObjectBytes)).isRight)

  test("fail closed: a count that disagrees with the in-flight transfer rejects, without damage"):
    val cs = chunksOf(bytes(1216)).map(decodeChunk)
    val ra = ChunkReassembler()
    ra.feed(cs(0)): Unit
    val liar: Envelope.KemChunk =
      Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 1, 4, bytes(ChunkCapacity, 9))
    assert(ra.feed(liar) == Left(ChunkError.CountMismatch))
    // The good transfer survives the bad envelope and still completes correctly.
    val done = cs.drop(1).flatMap(c => ra.feed(c).toOption.get)
    assert(done.size == 1 && done.head.bytes.sameElements(bytes(1216)))

  test("fail closed: a duplicate idx with DIFFERENT bytes rejects, without damaging the transfer"):
    val cs = chunksOf(bytes(ChunkCapacity * 3)).map(decodeChunk)
    val ra = ChunkReassembler()
    ra.feed(cs(0)): Unit
    val conflicting: Envelope.KemChunk =
      Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 3, bytes(ChunkCapacity, 3))
    assert(ra.feed(conflicting) == Left(ChunkError.ConflictingChunk))
    // An identical duplicate is still fine (ARQ retransmit), and the transfer completes intact.
    assert(ra.feed(cs(0)) == Right(None))
    val done = cs.drop(1).flatMap(c => ra.feed(c).toOption.get)
    assert(done.size == 1 && done.head.bytes.sameElements(bytes(ChunkCapacity * 3)))

  test("concurrent pending transfers are bounded: at the cap the OLDEST is evicted"):
    val ra = ChunkReassembler(maxPendingTransfers = 2)
    // Two distinct keys, each opened with a non-completing first chunk.
    assert(
      ra.feed(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(ChunkCapacity)))
        == Right(None)
    )
    assert(
      ra.feed(Envelope.KemChunk(2, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(ChunkCapacity)))
        == Right(None)
    )
    assert(ra.pendingCount == 2)
    // A third is ACCEPTED (never rejected) and evicts epoch 1, the oldest.
    assert(
      ra.feed(Envelope.KemChunk(3, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(ChunkCapacity)))
        == Right(None)
    )
    assert(ra.pendingCount == 2, "the cap still holds")
    // Epoch 1 was evicted: its second chunk opens a FRESH transfer rather than completing.
    assert(
      ra.feed(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 1, 2, bytes(4))) == Right(None)
    )
    // Epoch 3 (newest, still resident) completes normally.
    assert(
      ra.feed(Envelope.KemChunk(3, BuddyRole.Initiator, Part.Pub, 1, 2, bytes(4)))
        .toOption
        .get
        .exists(_.bytes.length == ChunkCapacity + 4)
    )

  test("a stale-epoch flood cannot permanently wedge a live rekey (self-healing cap)"):
    // The peer picks the epochs. If the cap rejected the NEWEST, a peer that opens N transfers and
    // never completes them would deny every future rekey for the process's lifetime, with no
    // recovery short of abandonAll(). Evicting the oldest keeps a live rekey always serviceable.
    val ra = ChunkReassembler(maxPendingTransfers = 4)
    for e <- 100 until 140 do // 40 stale, never-completed transfers
      assert(
        ra.feed(Envelope.KemChunk(e, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(ChunkCapacity)))
          == Right(None)
      )
      assert(ra.pendingCount <= 4, s"cap breached at epoch $e")
    // A genuine two-chunk rekey still completes immediately afterwards.
    val obj = bytes(ChunkCapacity + 9, 6)
    val cs = chunk(500, BuddyRole.Initiator, Part.Pub, obj).toOption.get.map(decodeChunk)
    assert(ra.feed(cs(0)) == Right(None))
    assert(
      ra.feed(cs(1)).toOption.get.exists(_.bytes.sameElements(obj)),
      "a live rekey must not be wedged by a stale flood"
    )

  test("abandonBefore(cutoff) reclaims every stale epoch in bulk, keeping current ones"):
    // Phase 3 advances epochs monotonically, so everything older than the current epoch is stale by
    // construction — and it cannot always enumerate the exact stale ids that abandon() requires.
    val ra = ChunkReassembler(maxPendingTransfers = 16)
    for e <- 1 to 6 do
      ra.feed(Envelope.KemChunk(e, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(ChunkCapacity))): Unit
    assert(ra.pendingCount == 6)
    assert(ra.abandonBefore(5) == 4, "epochs 1..4 are stale")
    assert(ra.pendingCount == 2, "epochs 5 and 6 survive")
    assert(ra.abandonBefore(5) == 0, "idempotent")
    assert(ra.abandonBefore(Int.MinValue) == 0, "nothing is before the minimum epoch")
    // The surviving current epoch still completes correctly.
    assert(
      ra.feed(Envelope.KemChunk(6, BuddyRole.Initiator, Part.Pub, 1, 2, bytes(2)))
        .toOption
        .get
        .isDefined
    )
    assert(ra.abandonBefore(Int.MaxValue) == 1, "epoch 5 remains and is reclaimable")

  test("abandon(epoch) releases a stalled transfer's slot (doc §4.4 wipe-on-abort/timeout)"):
    val ra = ChunkReassembler(maxPendingTransfers = 2)
    // Two epochs stall mid-transfer (a chunk never arrives; Phase 3 times the attempt out).
    ra.feed(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(ChunkCapacity))): Unit
    ra.feed(Envelope.KemChunk(2, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(ChunkCapacity))): Unit
    assert(ra.pendingCount == 2)
    assert(ra.abandon(1) == 1)
    assert(ra.pendingCount == 1, "only the abandoned epoch is dropped")
    // Epoch 2 was never touched by the abort and still completes correctly.
    val done = ra.feed(Envelope.KemChunk(2, BuddyRole.Initiator, Part.Pub, 1, 2, bytes(3)))
    assert(done.toOption.get.exists(_.bytes.length == ChunkCapacity + 3))
    assert(ra.abandon(999) == 0, "abandoning an unknown epoch is a no-op")
    // The abort genuinely dropped epoch 1's state: chunk 1 alone no longer completes it, it opens
    // a fresh pending transfer.
    assert(
      ra.feed(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 1, 2, bytes(4))) == Right(None)
    )

  test("completion returns intact bytes even though the buffer is wiped on release"):
    // Guards the ORDERING in the completion path: the object is copied out BEFORE the internal
    // zeroing. If the wipe ever moved ahead of the copy (or `bytes` came to alias the slots), the
    // caller would silently receive zeros — this pins that regression.
    val original = bytes(ChunkCapacity * 2 + 7, 4)
    val ra = ChunkReassembler()
    val done = chunksOf(original).map(decodeChunk).flatMap(c => ra.feed(c).toOption.get)
    assert(done.size == 1)
    assert(done.head.bytes.sameElements(original), "wipe-on-release must not zero the result")
    assert(done.head.bytes.exists(_ != 0.toByte), "sanity: the object is not all-zero anyway")

  test("exactly-once is bounded by the completed-key window: an evicted key CAN re-deliver"):
    // maxCompletedRemembered is the sole mechanism backing the documented exactly-once guarantee,
    // so pin its known limit rather than leave it prose-only (an off-by-one in the FIFO trim would
    // otherwise pass silently). Window = 1: completing epoch 2 evicts epoch 1's key.
    val ra = ChunkReassembler(maxCompletedRemembered = 1)
    val a = chunksOf(bytes(50, 1), epoch = 1).map(decodeChunk)
    val b = chunksOf(bytes(50, 2), epoch = 2).map(decodeChunk)
    assert(a.flatMap(c => ra.feed(c).toOption.get).size == 1)
    // While epoch 1's key is still remembered, a replay is correctly suppressed.
    assert(a.flatMap(c => ra.feed(c).toOption.get).isEmpty, "suppressed while remembered")
    assert(b.flatMap(c => ra.feed(c).toOption.get).size == 1) // evicts epoch 1 from the window
    // Epoch 1's key is now evicted: a replay re-delivers. This is the DOCUMENTED limit — upstream
    // ARQ dedup makes it non-occurring in practice and Phase 3 ignores non-current epochs.
    val replay = a.flatMap(c => ra.feed(c).toOption.get)
    assert(replay.size == 1, "an evicted key re-delivers — the documented bound of exactly-once")
    assert(replay.head.bytes.sameElements(bytes(50, 1)))

  test("the completed-key window retains exactly maxCompletedRemembered keys (FIFO trim)"):
    // Window = 2: completing epochs 2 and 3 evicts epoch 1 but must NOT evict 2 or 3 — an
    // off-by-one in the trim (>= vs >) would show up here.
    val ra = ChunkReassembler(maxCompletedRemembered = 2)
    def obj(e: Int) = chunksOf(bytes(40, e), epoch = e).map(decodeChunk)
    for e <- 1 to 3 do assert(obj(e).flatMap(c => ra.feed(c).toOption.get).size == 1)
    assert(obj(3).flatMap(c => ra.feed(c).toOption.get).isEmpty, "epoch 3 still remembered")
    assert(obj(2).flatMap(c => ra.feed(c).toOption.get).isEmpty, "epoch 2 still remembered")
    assert(obj(1).flatMap(c => ra.feed(c).toOption.get).size == 1, "epoch 1 evicted ⇒ re-delivers")

  test("abandon does not resurrect a completed object (exactly-once survives an abort)"):
    val cs = chunksOf(bytes(300)).map(decodeChunk)
    val ra = ChunkReassembler()
    val first = cs.flatMap(c => ra.feed(c).toOption.get)
    assert(first.size == 1)
    assert(ra.abandon(1) == 0, "a completed transfer has no pending state to abandon")
    // A late duplicate after the abort must still not re-deliver.
    assert(cs.flatMap(c => ra.feed(c).toOption.get).isEmpty)

  test("abandonAll drops every pending transfer and frees all slots"):
    val ra = ChunkReassembler(maxPendingTransfers = 2)
    ra.feed(Envelope.KemChunk(1, BuddyRole.Initiator, Part.Pub, 0, 2, bytes(ChunkCapacity))): Unit
    ra.feed(Envelope.KemChunk(1, BuddyRole.Responder, Part.Ct, 0, 2, bytes(ChunkCapacity))): Unit
    assert(ra.abandonAll() == 2)
    assert(ra.pendingCount == 0)
    assert(ra.abandonAll() == 0)

  test("the envelope is wide enough for every fixed-offset field (pinned, not assumed)"):
    // `decode` bounds-checks the total width then reads fixed offsets; that is sound only while the
    // region holds the widest fixed field set. Pinned so a narrowed inner block fails loudly at
    // load instead of turning a strict decode into an out-of-bounds read on attacker input.
    assert(EnvelopeBytes >= ChunkHeaderBytes)
    assert(EnvelopeBytes >= 6 + ConfirmTagBytes)
    assert(ChunkCapacity >= 1)

  test("property: a single-bit flip anywhere in an envelope either decodes sanely or fails closed"):
    // The exhaustive fail-closed contract: NO input of the right width may crash the decoder, and
    // anything it does accept must satisfy the field invariants (never idx >= count, never a data
    // length past the buffer). This is the property the individual cases above sample.
    val base = encode(
      Envelope.KemChunk(0x0a0b0c0d, BuddyRole.Initiator, Part.Pub, 1, 3, bytes(ChunkCapacity, 4))
    )
    forAll(Gen.choose(0, EnvelopeBytes - 1), Gen.choose(0, 7)) { (pos, bit) =>
      val flipped = corrupt(base)(a => a(pos) = (a(pos) ^ (1 << bit)).toByte)
      decode(flipped) match
        case Left(_) => succeed // fail-closed
        case Right(Envelope.KemChunk(e, _, _, idx, count, data)) =>
          assert(e >= 0 && count >= 1 && count <= MaxChunkCount)
          assert(idx >= 0 && idx < count)
          assert(data.length <= ChunkCapacity && ChunkHeaderBytes + data.length <= EnvelopeBytes)
        case Right(_) => succeed // a different (well-formed) type
    }

  test("property: arbitrary right-width garbage never crashes the decoder"):
    val genEnvelope: Gen[Array[Byte]] =
      Gen.listOfN(EnvelopeBytes, Gen.choose(Byte.MinValue, Byte.MaxValue)).map(_.toArray)
    forAll(genEnvelope) { g =>
      decode(g) match
        case Left(_) => succeed
        case Right(_) => succeed
    }

  // ------------------------------------------------------------------------ scheduler policy

  import ChunkScheduler.*

  test("scheduler: an idle round with a pending chunk is ALWAYS spent on the chunk (a-i)"):
    // Doc §3.1 (a-i): the chunk frame REPLACES the cover write, so it costs zero marginal frames.
    val (d, s) = decide(State.Initial, chunkPending = true, contentPending = false, Policy.Default)
    assert(d == Decision.Chunk)
    assert(s == State.Initial, "an idle spend must not consume the busy-round budget")

  test("scheduler: a fully idle channel drains a 9-chunk transfer in 9 rounds"):
    var st = State.Initial
    val decisions = (1 to 9).map { _ =>
      val (d, s) = decide(st, chunkPending = true, contentPending = false, Policy.Default)
      st = s
      d
    }
    assert(decisions.forall(_ == Decision.Chunk))

  test("scheduler: with nothing pending the round writes cover; content beats cover"):
    assert(decide(State.Initial, false, false, Policy.Default)._1 == Decision.Cover)
    assert(decide(State.Initial, false, true, Policy.Default)._1 == Decision.Content)
    assert(decide(State(3), false, true, Policy.Default)._2 == State(0), "no transfer ⇒ reset")

  test("scheduler: never Chunk without a pending chunk; never Cover with anything pending"):
    for
      st <- Seq(State.Initial, State(1), State(3), State(99))
      cp <- Seq(true, false)
      tp <- Seq(true, false)
      k <- Seq(2, 3, 4, 8)
    do
      val (d, _) = decide(st, cp, tp, Policy(k))
      if !cp then assert(d != Decision.Chunk, s"chunk without pending: $st/$cp/$tp/$k")
      if cp || tp then assert(d != Decision.Cover, s"cover with pending work: $st/$cp/$tp/$k")

  test("scheduler: a busy channel cedes at most 1 in busyStride rounds to chunks"):
    for k <- Seq(2, 3, 4, 8) do
      var st = State.Initial
      val rounds = 200
      val ds = (1 to rounds).map { _ =>
        val (d, s) = decide(st, chunkPending = true, contentPending = true, Policy(k))
        st = s
        d
      }
      val chunks = ds.count(_ == Decision.Chunk)
      assert(chunks <= rounds / k, s"k=$k: $chunks chunk rounds > ${rounds / k}")
      assert(chunks > 0, s"k=$k: a busy channel must still make rekey progress (no starvation)")
      assert(ds.count(_ == Decision.Content) == rounds - chunks, s"k=$k: busy rounds are content")

  test("property: the busy-round chunk fraction bound holds under ANY pending interleaving"):
    // The doc's guarantee is about BUSY rounds (idle spends are free), so the oracle counts only
    // rounds where content was also pending. Random scripts, mirroring ArqStressSpec's style.
    val genRound: Gen[(Boolean, Boolean)] =
      for { c <- Gen.oneOf(true, false); t <- Gen.oneOf(true, false) } yield (c, t)
    forAll(Gen.choose(0, 300).flatMap(Gen.listOfN(_, genRound)), Gen.choose(2, 8)) { (script, k) =>
      var st = State.Initial
      var busy = 0
      var busyChunks = 0
      script.foreach { case (cp, tp) =>
        val (d, s) = decide(st, cp, tp, Policy(k))
        if cp && tp then
          busy += 1
          if d == Decision.Chunk then busyChunks += 1
        st = s
      }
      assert(
        busyChunks <= busy / k,
        s"k=$k: $busyChunks busy chunk rounds of $busy (> ${busy / k})"
      )
    }

  test("scheduler: busyStride < 2 is rejected (k=1 would starve content)"):
    assertThrows[IllegalArgumentException](Policy(1))
    assertThrows[IllegalArgumentException](Policy(0))
    assertThrows[IllegalArgumentException](Policy(-1))
