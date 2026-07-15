package engine

import scala.collection.mutable

/** Chunked control sub-stream over the stop-and-wait ARQ transport — Phase 2 of the continuous
  * post-quantum ratchet plan (`specs/001-metadata-private-messenger/design/continuous-pq-ratchet.md`
  * §3.1 chunk framing, §7 Phase 2). TRANSPORT ONLY: this module moves opaque bytes; it performs no
  * crypto and mutates no ratchet state. Phase 3 wires it into `Engine`'s tick loop, where it carries
  * the periodic rekey's KEM material as ordinary ARQ messages. Nothing here changes the wire frame:
  * the envelope lives INSIDE the ARQ padded-payload region (`ArqFrame.PayloadBytes`), which is itself
  * sealed inside the ratchet inner block, so every frame the store sees remains the same uniform 256
  * bytes (design doc §5; FR-012).
  *
  * Envelope layout (fixed width = `ArqFrame.PayloadBytes` = 156, zero-padded after the fields):
  * {{{
  * KEM_CHUNK:    type(1)=0x01 ‖ epoch(4 BE) ‖ role(1) ‖ part(1) ‖ idx(1) ‖ count(1) ‖
  *               dataLen(2 BE) ‖ data(≤145) ‖ zero pad
  * KEM_CONFIRM:  type(1)=0x02 ‖ epoch(4 BE) ‖ role(1) ‖ tag(32) ‖ zero pad
  * EPOCH_COMMIT: type(1)=0x03 ‖ epoch(4 BE) ‖ role(1) ‖ anchor(4 BE) ‖ zero pad
  * }}}
  * The design doc sketches a 9-byte KEM_CHUNK header (⇒ 147 data bytes) and calls the final byte
  * budget "an implementation detail"; this implementation adds an explicit 2-byte big-endian
  * `dataLen` (the codebase's `Frame.pad` length-prefix convention) so the final, partial chunk is
  * unambiguous without trusting zero-padding — an 11-byte header, 145 data bytes per chunk. The
  * doc's frame counts are unchanged: hybrid pubkey 1216 B ⇒ ⌈1216/145⌉ = 9 frames, ciphertext
  * 1120 B ⇒ 8 frames, ~19 frames per full rekey.
  *
  * `EPOCH_COMMIT` additionally carries a 4-byte `anchor` the doc's §3.1 sketch ("type ‖ epoch ‖
  * role — fold now") does not name. It is the ROOT INDEX the fold applies to (`DoubleRatchet
  * .rootIndex`), which §4.2 requires the fold be "deterministically anchored to" so both sides
  * derive the byte-identical `RK_epoch`. Sending it EXPLICITLY lets the receiver check its own live
  * root index against the committer's and REFUSE on a mismatch (`Engine` records the fixed reason
  * `pq_rekey_anchor_mismatch`) instead of folding at the wrong position and diverging silently —
  * i.e. it converts the doc's implicit ratchet-position assumption into a fail-closed check. The field
  * is padding-space in the old layout, so `anchor = 0` re-encodes byte-identically to the Phase 2
  * vector; the pinned KAT in `ChunkStreamCrossSpec` is unchanged.
  *
  * Control-vs-content discrimination (byte 0): user content occupies this same region via
  * `Frame.pad(msg, ArqFrame.PayloadBytes)`, whose first byte is the high byte of a big-endian
  * length ≤ `Frame.maxPayload(156)` = 154 < 256 — i.e. ALWAYS 0x00. All control type tags are
  * nonzero, so byte 0 discriminates exactly; user content cannot spoof a control envelope and a
  * control envelope cannot decode as content. Asserted at object initialization and pinned in
  * tests against the real constants.
  *
  * Privacy note (Constitution II, honest by design): chunk counts, indices, epochs, and timing are
  * PUBLIC metadata to the two endpoints — they describe the rekey transfer itself and carry no
  * secret-dependent branching. The untrusted store never sees any of it: envelopes travel only
  * inside the MK-sealed inner block of uniform 256-byte frames, indistinguishable from content or
  * cover frames (design doc §5).
  *
  * Decoding is strict and fail-closed: wrong width, unknown type, negative epoch, bad role/part,
  * `idx ≥ count`, `count` outside `[1, MaxChunkCount]`, non-canonical data length, or nonzero
  * bytes in the padding all reject with a fixed error and no partial result. Every read is bounds-
  * checked against the actual buffer; declared lengths are never trusted beyond it.
  */
object ChunkStream:

  /** The envelope occupies the FULL ARQ padded-payload region — single-sourced from the real
    * transport constant, never a copied literal (156 today). */
  val EnvelopeBytes: Int = ArqFrame.PayloadBytes

  /** KEM_CHUNK header: type(1) + epoch(4) + role(1) + part(1) + idx(1) + count(1) + dataLen(2). */
  val ChunkHeaderBytes: Int = 11

  /** Max KEM-material bytes one KEM_CHUNK envelope carries (145 today). */
  val ChunkCapacity: Int = EnvelopeBytes - ChunkHeaderBytes

  /** Width of a KEM_CONFIRM tag (mirrors `KeySchedule.pqConfirmTag*`, 32-byte HMAC output). */
  val ConfirmTagBytes: Int = 32

  /** Hard cap on `count` — bounds reassembly memory against an attacker-influenceable field. The
    * doc's budget is ≤9 chunks per object (hybrid pubkey 1216 B); 32 gives ample headroom while
    * capping a pending transfer at 32 × 145 ≈ 4.6 KB (design doc §3.1). */
  val MaxChunkCount: Int = 32

  /** Largest object `chunk` accepts (= `MaxChunkCount` full chunks; 4640 B today — the hybrid
    * pubkey/ciphertext are 1216/1120 B, well within). */
  val MaxObjectBytes: Int = MaxChunkCount * ChunkCapacity

  // Type tags — all NONZERO (byte-0 discrimination vs Frame.pad'ed content; see the object doc).
  private val TagKemChunk: Byte = 0x01
  private val TagKemConfirm: Byte = 0x02
  private val TagEpochCommit: Byte = 0x03

  // Byte 0 of a Frame.pad'ed content payload is the BE-high length byte; it can only be 0x00 while
  // the max payload of the region stays below 256, which is what makes the nonzero tags sound.
  require(
    frame.Frame.maxPayload(EnvelopeBytes) < 256,
    "byte-0 control/content discrimination requires maxPayload(region) < 256"
  )

  // `decode` bounds-checks only the TOTAL width, then reads its fixed-offset fields directly; that
  // is sound exactly while the envelope is wide enough to hold the widest fixed field set. Today
  // the region is 156 B, so this holds with room to spare — but the margin is DERIVED from
  // `DoubleRatchet.InnerSize`, so pin it here: if the inner block ever narrowed, this fails loudly
  // at load rather than turning a strict decode into an out-of-bounds read on attacker input.
  require(
    EnvelopeBytes >= ChunkHeaderBytes && EnvelopeBytes >= 6 + ConfirmTagBytes &&
      EnvelopeBytes >= 6 + 4,
    s"envelope $EnvelopeBytes too narrow for the fixed control fields"
  )
  require(ChunkCapacity >= 1, "a KEM_CHUNK must carry at least one payload byte")

  /** Which bulky KEM object a chunk belongs to (doc §3.1: pubkey vs ciphertext). */
  enum Part:
    case Pub, Ct

  private def roleByte(r: BuddyRole): Byte = r match
    case BuddyRole.Initiator => 0x01
    case BuddyRole.Responder => 0x02
  private def partByte(p: Part): Byte = p match
    case Part.Pub => 0x01
    case Part.Ct => 0x02

  /** Fixed, parameterless rejection reasons — fail closed, nothing attacker-controlled echoed. */
  enum ChunkError:
    case BadLength, UnknownType, BadEpoch, BadRole, BadPart, BadIndex, BadCount, BadDataLength,
      NonZeroPadding, OversizeObject, CountMismatch, ConflictingChunk, BadAnchor

  /** A decoded control envelope. `data`/`tag` are the decoder's own copies (never aliases into the
    * input buffer). Constructed values fed to [[ChunkReassembler.feed]] are re-validated there. */
  enum Envelope:
    case KemChunk(
        epoch: Int,
        role: BuddyRole,
        part: Part,
        idx: Int,
        count: Int,
        data: Array[Byte]
    )
    case KemConfirm(epoch: Int, role: BuddyRole, tag: Array[Byte])

    /** "Fold now" — `anchor` is the `DoubleRatchet.rootIndex` the epoch fold applies to (see the
      * object doc). The sender arms it as its OWN next root index; the receiver, after processing
      * this frame, is at exactly that index and folds immediately, refusing on any mismatch. */
    case EpochCommit(epoch: Int, role: BuddyRole, anchor: Int)

  /** True iff a full-width ARQ padded payload holds a control envelope (nonzero byte 0) rather
    * than `Frame.pad`'ed user content. Phase 3's receive path branches on this. */
  def isControl(paddedPayload: Array[Byte]): Boolean =
    paddedPayload.length == EnvelopeBytes && paddedPayload(0) != 0

  /** Canonical-form KEM_CHUNK field validation, shared by the decoder and the reassembler (the
    * reassembler re-checks because an `Envelope.KemChunk` can be constructed directly). Canonical
    * means: every chunk except the last is exactly full, and an empty last chunk exists only as
    * the sole chunk of an empty object — so `(idx, count, dataLen)` determine offsets uniquely. */
  private[engine] def validateChunkFields(
      epoch: Int,
      idx: Int,
      count: Int,
      dataLen: Int
  ): Option[ChunkError] =
    if epoch < 0 then Some(ChunkError.BadEpoch)
    else if count < 1 || count > MaxChunkCount then Some(ChunkError.BadCount)
    else if idx < 0 || idx >= count then Some(ChunkError.BadIndex)
    else if dataLen < 0 || dataLen > ChunkCapacity then Some(ChunkError.BadDataLength)
    else if idx < count - 1 && dataLen != ChunkCapacity then Some(ChunkError.BadDataLength)
    else if idx == count - 1 && count > 1 && dataLen == 0 then Some(ChunkError.BadDataLength)
    else None

  /** Encode an envelope into exactly [[EnvelopeBytes]] (the width `ArqFrame.encode` requires),
    * zero-padded after the fields. Sender-side inputs are locally produced, so invalid fields fail
    * loudly (`require`), matching `ArqFrame.encode`; attacker-facing strictness lives in
    * [[decode]]. */
  def encode(env: Envelope): Array[Byte] =
    val out = new Array[Byte](EnvelopeBytes) // zero-filled ⇒ padding is zero by construction
    def putEpoch(epoch: Int): Unit =
      require(epoch >= 0, s"epoch $epoch < 0")
      out(1) = ((epoch >>> 24) & 0xff).toByte
      out(2) = ((epoch >>> 16) & 0xff).toByte
      out(3) = ((epoch >>> 8) & 0xff).toByte
      out(4) = (epoch & 0xff).toByte
    env match
      case Envelope.KemChunk(epoch, role, part, idx, count, data) =>
        val bad = validateChunkFields(epoch, idx, count, data.length)
        require(bad.isEmpty, s"invalid KEM_CHUNK fields: ${bad.getOrElse("")}")
        out(0) = TagKemChunk
        putEpoch(epoch)
        out(5) = roleByte(role)
        out(6) = partByte(part)
        out(7) = idx.toByte
        out(8) = count.toByte
        out(9) = ((data.length >>> 8) & 0xff).toByte
        out(10) = (data.length & 0xff).toByte
        System.arraycopy(data, 0, out, ChunkHeaderBytes, data.length)
      case Envelope.KemConfirm(epoch, role, tag) =>
        require(tag.length == ConfirmTagBytes, s"tag ${tag.length} != $ConfirmTagBytes")
        out(0) = TagKemConfirm
        putEpoch(epoch)
        out(5) = roleByte(role)
        System.arraycopy(tag, 0, out, 6, ConfirmTagBytes)
      case Envelope.EpochCommit(epoch, role, anchor) =>
        require(anchor >= 0, s"anchor $anchor < 0")
        out(0) = TagEpochCommit
        putEpoch(epoch)
        out(5) = roleByte(role)
        out(6) = ((anchor >>> 24) & 0xff).toByte
        out(7) = ((anchor >>> 16) & 0xff).toByte
        out(8) = ((anchor >>> 8) & 0xff).toByte
        out(9) = (anchor & 0xff).toByte
    out

  /** Strict decode of a full-width padded payload. Fail-closed: any malformation rejects with a
    * fixed [[ChunkError]] and no partial result. The input width is pinned first, so every fixed-
    * offset read below is in bounds; the only variable length (`dataLen`) is checked against
    * [[ChunkCapacity]] (and canonical form) before any use. */
  def decode(padded: Array[Byte]): Either[ChunkError, Envelope] =
    if padded.length != EnvelopeBytes then Left(ChunkError.BadLength)
    else
      val epoch = ((padded(1) & 0xff) << 24) | ((padded(2) & 0xff) << 16) |
        ((padded(3) & 0xff) << 8) | (padded(4) & 0xff)
      def role: Either[ChunkError, BuddyRole] = padded(5) match
        case 0x01 => Right(BuddyRole.Initiator)
        case 0x02 => Right(BuddyRole.Responder)
        case _ => Left(ChunkError.BadRole)
      def zeroPaddedFrom(off: Int): Boolean =
        var i = off
        var ok = true
        while i < EnvelopeBytes do
          if padded(i) != 0 then ok = false
          i += 1
        ok
      if epoch < 0 then Left(ChunkError.BadEpoch)
      else
        padded(0) match
          case TagKemChunk =>
            role.flatMap { r =>
              val part = padded(6) match
                case 0x01 => Right(Part.Pub)
                case 0x02 => Right(Part.Ct)
                case _ => Left(ChunkError.BadPart)
              part.flatMap { p =>
                val idx = padded(7) & 0xff
                val count = padded(8) & 0xff
                val dataLen = ((padded(9) & 0xff) << 8) | (padded(10) & 0xff)
                validateChunkFields(epoch, idx, count, dataLen) match
                  case Some(err) => Left(err)
                  case None =>
                    if !zeroPaddedFrom(ChunkHeaderBytes + dataLen) then
                      Left(ChunkError.NonZeroPadding)
                    else
                      val data = new Array[Byte](dataLen)
                      System.arraycopy(padded, ChunkHeaderBytes, data, 0, dataLen)
                      Right(Envelope.KemChunk(epoch, r, p, idx, count, data))
              }
            }
          case TagKemConfirm =>
            role.flatMap { r =>
              if !zeroPaddedFrom(6 + ConfirmTagBytes) then Left(ChunkError.NonZeroPadding)
              else
                val tag = new Array[Byte](ConfirmTagBytes)
                System.arraycopy(padded, 6, tag, 0, ConfirmTagBytes)
                Right(Envelope.KemConfirm(epoch, r, tag))
            }
          case TagEpochCommit =>
            role.flatMap { r =>
              val anchor = ((padded(6) & 0xff) << 24) | ((padded(7) & 0xff) << 16) |
                ((padded(8) & 0xff) << 8) | (padded(9) & 0xff)
              if anchor < 0 then Left(ChunkError.BadAnchor) // high bit set ⇒ never a root index
              else if !zeroPaddedFrom(10) then Left(ChunkError.NonZeroPadding)
              else Right(Envelope.EpochCommit(epoch, r, anchor))
            }
          case _ => Left(ChunkError.UnknownType)

  /** Split an arbitrary byte string into encoded, full-width KEM_CHUNK envelopes with correct
    * `idx`/`count` (canonical form: all chunks full except the last; an empty object is one empty
    * chunk). Each element is ready to be an ARQ padded payload. `Left(OversizeObject)` beyond
    * [[MaxObjectBytes]] — data-dependent, so an `Either` rather than a `require`. */
  def chunk(
      epoch: Int,
      role: BuddyRole,
      part: Part,
      bytes: Array[Byte]
  ): Either[ChunkError, Vector[Array[Byte]]] =
    if bytes.length > MaxObjectBytes then Left(ChunkError.OversizeObject)
    else
      val count = math.max(1, (bytes.length + ChunkCapacity - 1) / ChunkCapacity)
      val out = Vector.newBuilder[Array[Byte]]
      var idx = 0
      while idx < count do
        val off = idx * ChunkCapacity
        val len = math.min(ChunkCapacity, bytes.length - off)
        val data = new Array[Byte](len)
        System.arraycopy(bytes, off, data, 0, len)
        out += encode(Envelope.KemChunk(epoch, role, part, idx, count, data))
        idx += 1
      Right(out.result())

/** Reassembles KEM objects from (possibly duplicated or reordered) KEM_CHUNK envelopes, keyed by
  * `(epoch, role, part)` (design doc §3.1: "buffers `count` chunks keyed by `(epoch, part)` and
  * completes when all `idx ∈ [0, count)` are present" — `role` is included as a defensive
  * refinement so opposite-role chunks can never collide). The ARQ layer beneath already delivers
  * in order and de-duplicates; this layer is defensive on top of it (doc §3.1):
  *
  *   - Exactly-once: an object is yielded once, when its last missing chunk arrives; late
  *     duplicates for a completed key are ignored (within the bounded remembered-completions
  *     window — see below).
  *   - Fail-closed on inconsistency: a `count` that disagrees with the transfer's, or a duplicate
  *     `idx` carrying different bytes, is rejected with a fixed error; the pending transfer is
  *     left intact, so a bad envelope cannot destroy a good transfer.
  *   - Bounded memory against attacker-influenceable fields: `count ≤ ChunkStream.MaxChunkCount`
  *     per transfer, at most `maxPendingTransfers` concurrent transfers, and a FIFO-bounded set of
  *     `maxCompletedRemembered` completed keys.
  *   - No permanent wedge: the peer picks the epochs, so at the cap the OLDEST pending transfer is
  *     evicted rather than the new one rejected. Rejecting-the-newest would let a peer that opens
  *     `maxPendingTransfers` transfers and never completes them deny every future rekey for the
  *     process's lifetime. Eviction is self-healing — a live rekey always gets a slot — and Phase 3
  *     should additionally call [[abandonBefore]] on each epoch advance for prompt, in-order
  *     reclamation ([[abandon]] only helps when the caller still knows the exact stale epoch).
  *   - Exactly-once is bounded by `maxCompletedRemembered` (16 by default): a duplicate of a key
  *     evicted from that window would start a fresh transfer and could re-deliver. Upstream ARQ
  *     dedup makes duplicates non-occurring in practice and Phase 3's epoch state machine ignores
  *     non-current epochs, but the limit is real — it is pinned by test, not just described here.
  *
  * ONE INSTANCE PER PAIR (Phase 3: alongside the other per-pair ARQ state in `BuddyRuntime`). The
  * key has no pair id, and the eviction policy above assumes a single peer supplies every chunk: a
  * peer can then only evict its OWN stalled transfer. A reassembler SHARED across buddies would let
  * one malicious peer evict another buddy's live transfer — turning a self-inflicted stall into a
  * cross-buddy denial of service. Not thread-safe (mutable, single-owner) — same discipline as the
  * rest of the engine state. */
final class ChunkReassembler(
    maxPendingTransfers: Int = ChunkReassembler.DefaultMaxPendingTransfers,
    maxCompletedRemembered: Int = ChunkReassembler.DefaultMaxCompletedRemembered
):
  import ChunkStream.*
  import ChunkReassembler.{Completed, Key}

  require(maxPendingTransfers >= 1, "maxPendingTransfers must be >= 1")
  require(maxCompletedRemembered >= 1, "maxCompletedRemembered must be >= 1")

  private final class Pending(val count: Int):
    val slots: Array[Array[Byte]] = new Array[Array[Byte]](count)
    var received: Int = 0

  // Insertion-ordered so the cap can evict the OLDEST pending transfer rather than reject the
  // newest — see `feed`. `mutable.LinkedHashMap` iterates in insertion order on both platforms.
  private val pending = mutable.LinkedHashMap.empty[Key, Pending]
  private val completedKeys = mutable.ArrayDeque.empty[Key] // FIFO window, newest last

  /** Zero a transfer's buffered chunks before dropping it, mirroring `Engine.wipe`
    * (`Engine.scala:227`). The buffered material is PUBLIC (a KEM public key / ciphertext), so this
    * is defensive rather than a secrecy requirement — it makes the release actually release, and
    * keeps the invariant true if Phase 3 ever routes non-public bytes through this buffer. */
  private def wipe(p: Pending): Unit =
    var s = 0
    while s < p.slots.length do
      val slot = p.slots(s)
      if slot != null then
        var i = 0
        while i < slot.length do
          slot(i) = 0.toByte
          i += 1
      s += 1

  private def release(key: Key): Unit =
    pending.remove(key).foreach(wipe)

  /** Feed one KEM_CHUNK. `Right(Some(_))` exactly when this chunk completes its object;
    * `Right(None)` for an accepted-but-incomplete chunk or an exact duplicate; `Left` fail-closed
    * on any inconsistency (the pending transfer, if any, is left unchanged). */
  def feed(c: Envelope.KemChunk): Either[ChunkError, Option[Completed]] =
    // Re-validate: this value may have been constructed directly, not via the strict decoder.
    validateChunkFields(c.epoch, c.idx, c.count, c.data.length) match
      case Some(err) => Left(err)
      case None =>
        val key = Key(c.epoch, c.role, c.part)
        if completedKeys.contains(key) then Right(None) // late duplicate after completion
        else
          pending.get(key) match
            case Some(p) if p.count != c.count => Left(ChunkError.CountMismatch)
            case Some(p) => store(key, p, c)
            case None =>
              // At the cap, evict the OLDEST pending transfer rather than reject this one. The
              // peer chooses the epochs, so rejecting-the-newest let a peer that opens
              // `maxPendingTransfers` transfers and never completes them wedge every future rekey
              // permanently — Phase 3 ignoring a stale epoch does not free a slot `feed` already
              // allocated, and `abandon` needs the exact stale epoch to reclaim. Evicting the
              // oldest is self-healing: a live rekey always gets a slot, and the worst a flood can
              // do is stall its own transfer. Phase 3 should still call `abandonBefore` on each
              // epoch advance for prompt, in-order reclamation.
              if pending.size >= maxPendingTransfers then
                pending.headOption.foreach((oldest, _) => release(oldest))
              val p = new Pending(c.count)
              pending(key) = p
              store(key, p, c)

  private def store(
      key: Key,
      p: Pending,
      c: Envelope.KemChunk
  ): Either[ChunkError, Option[Completed]] =
    p.slots(c.idx) match
      case prior if prior != null =>
        if prior.length == c.data.length && prior.sameElements(c.data) then Right(None) // dup
        else Left(ChunkError.ConflictingChunk)
      case _ =>
        p.slots(c.idx) = c.data.clone() // own copy: the caller's array must not alias our state
        p.received += 1
        if p.received < p.count then Right(None)
        else
          var total = 0
          p.slots.foreach(s => total += s.length)
          val bytes = new Array[Byte](total)
          var off = 0
          p.slots.foreach { s =>
            System.arraycopy(s, 0, bytes, off, s.length)
            off += s.length
          }
          release(key) // the bytes are copied out above; zero and drop the buffer
          completedKeys.append(key)
          if completedKeys.size > maxCompletedRemembered then completedKeys.removeHead(): Unit
          Right(Some(Completed(c.epoch, c.role, c.part, bytes)))

  /** Drop every pending (incomplete) transfer for `epoch`, zeroing its buffers, and return how many
    * were dropped. A rekey attempt aborts as a whole — on timeout, on a failed confirmation, or
    * when the epoch is abandoned — and the design doc requires the attempt's state be released then
    * (§4.4: "wipe on abort/timeout … so a stalled rekey does not leave [material] resident
    * indefinitely"). Phase 3 calls this from its abort path. Completed-key suppression is
    * untouched, so a late duplicate of an already-yielded object still cannot re-deliver. */
  def abandon(epoch: Int): Int = releaseWhere(_.epoch == epoch)

  /** Drop every pending transfer for an epoch STRICTLY BEFORE `cutoff` (zeroing buffers), returning
    * how many were dropped. Phase 3 calls this on each epoch advance to reclaim in bulk: epochs are
    * monotonic, so anything older than the current one is stale by construction and needs no
    * enumeration. [[abandon]] can only reclaim an epoch whose exact id the caller still knows,
    * which a stalled or never-tracked attempt may not be. */
  def abandonBefore(cutoff: Int): Int = releaseWhere(_.epoch < cutoff)

  /** Drop ALL pending transfers, zeroing buffers (e.g. tearing a pair down). Completed-key
    * suppression is retained. */
  def abandonAll(): Int = releaseWhere(_ => true)

  private def releaseWhere(p: Key => Boolean): Int =
    val doomed = pending.keysIterator.filter(p).toVector
    doomed.foreach(release)
    doomed.size

  /** Pending (incomplete) transfer count — observability for Phase 3's timeout logic and tests. */
  def pendingCount: Int = pending.size

object ChunkReassembler:
  /** One in-flight rekey needs 2 transfers (pub + ct); 8 leaves headroom without unbounding it. */
  val DefaultMaxPendingTransfers: Int = 8

  /** Completed keys remembered for late-duplicate suppression (see the class doc). */
  val DefaultMaxCompletedRemembered: Int = 16

  /** Reassembly key (design doc §3.1, plus `role` — see the class doc). */
  final case class Key(epoch: Int, role: BuddyRole, part: ChunkStream.Part)

  /** A fully reassembled KEM object. `bytes` is owned by the caller (a fresh array). */
  final case class Completed(
      epoch: Int,
      role: BuddyRole,
      part: ChunkStream.Part,
      bytes: Array[Byte]
  )

/** Scheduler policy for spending a round's SINGLE store write (FR-012) on a control chunk — the
  * doc's option (a-i) + (a-ii) hybrid (§3.1 "Interleaving with live traffic"): spend idle rounds
  * first (a chunk frame replaces what would otherwise be a cover write — zero marginal frames, and
  * the store sees the same one uniform write per round either way), and on busy rounds cede at
  * most a bounded fraction (≤ 1 in `busyStride`) to chunks so content is never starved (the doc's
  * head-of-line caveat). Pure and engine-decoupled: Phase 3 consults it from the tick loop when a
  * new ARQ head opens (once per head rather than once per round — stop-and-wait pins one message
  * across many rounds, so a per-round vote would not describe the lane share). Inputs are booleans and a counter — no payload bytes, so
  * nothing here can be secret-dependent (Constitution II). */
object ChunkScheduler:

  /** What this round's single write should carry. `Content` covers both a queued head and an
    * ack-only frame (any real, non-chunk frame the engine wants to send); `Cover` is the idle
    * cover write. */
  enum Decision:
    case Chunk, Content, Cover

  /** `busyStride` = k in the doc's "≤ 1 in k" busy-round bound (§3.1 (a-ii)). k ≥ 2, so content
    * always gets a strict majority of busy rounds (k = 1 would starve content during a rekey —
    * the head-of-line failure mode the doc calls out). */
  final case class Policy(busyStride: Int):
    require(busyStride >= 2, s"busyStride $busyStride < 2 would starve content on busy rounds")

  object Policy:
    /** Content keeps 3 of every 4 busy rounds; a 9-chunk pubkey transfer over a fully busy
      * channel takes ≤ 36 rounds. Cadence is a Phase 3 policy knob (doc §9 open question 2). */
    val Default: Policy = Policy(busyStride = 4)

  /** Busy rounds spent on content since the last busy-round chunk spend (idle chunk spends are
    * free and do not touch it). Immutable — `decide` returns the successor state. */
  final case class State(busyRoundsSinceChunk: Int)

  object State:
    val Initial: State = State(0)

  /** Decide this round's single write. `chunkPending` = a control chunk awaits transmission;
    * `contentPending` = the engine has a real non-chunk frame to send (queued head or owed ack).
    *
    * Guarantees (property-tested in `ChunkStreamSpec`):
    *   - Idle-first: `chunkPending && !contentPending` always yields `Chunk` (replacing the cover
    *     write; zero marginal frames).
    *   - Bounded busy fraction: from `State.Initial`, any execution spends at most
    *     `⌊busyRounds / busyStride⌋` busy rounds on chunks — every busy chunk spend is preceded by
    *     ≥ `busyStride − 1` busy content rounds since the counter last reset.
    *   - Never `Chunk` without `chunkPending`; never `Cover` when anything is pending. */
  def decide(
      state: State,
      chunkPending: Boolean,
      contentPending: Boolean,
      policy: Policy
  ): (Decision, State) =
    if !chunkPending then
      // No transfer in progress: counter resets so the next transfer earns busy spends afresh.
      (if contentPending then Decision.Content else Decision.Cover, State(0))
    else if !contentPending then (Decision.Chunk, state) // idle round: spend it first (a-i)
    else if state.busyRoundsSinceChunk >= policy.busyStride - 1 then (Decision.Chunk, State(0))
    else (Decision.Content, State(state.busyRoundsSinceChunk + 1))
