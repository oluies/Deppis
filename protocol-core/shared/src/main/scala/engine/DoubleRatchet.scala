package engine

import java.nio.charset.StandardCharsets.UTF_8
import scala.collection.mutable

/** The **DH double ratchet with header encryption** — post-compromise security (PCS) for the content
  * path, the follow-up to the forward-secret symmetric ratchet (`KeySchedule`). Specified in
  * `specs/001-metadata-private-messenger/design/dh-ratchet.md`; implemented faithfully to the
  * published Signal "Double Ratchet with header encryption" algorithm (Constitution I construction
  * amendment v1.1.0: assembled from vetted primitives — `x25519.X25519`, `kdf.Kdf.hmacSha256`,
  * `aead.Aead` — under KATs + these property tests + the threat-model doc; no primitive hand-rolled).
  *
  * Why a DH ratchet: the symmetric ratchet wipes used keys (forward secrecy) but a captured live chain
  * key still derives every FUTURE message — the chain only advances via a public one-way HMAC. Each DH
  * step mixes a FRESH random X25519 secret into the root key, so one uncompromised step re-secures the
  * session (healing). See dh-ratchet.md §1.
  *
  * Why header encryption (the metadata-privacy twist, dh-ratchet.md §2): a DH ratchet's public key is
  * constant across a whole sending chain. In clear it would let the store LINK a chain's frames,
  * breaking unlinkability. So the header (ratchet pubkey + counters) is AEAD-sealed under a header-key
  * chain; the receiver trial-decrypts against its current/next header keys without ever seeing the
  * pubkey. To the store, header ciphertext is just more uniform random bytes.
  *
  * Pure cross-platform Scala: compiles to JVM (JCA primitives) and Scala.js (`@noble`) identically;
  * the property tests run on both. Mutable by design (a ratchet IS evolving state); every retired key
  * — `RK`, chain keys, message keys, header keys, skipped keys, DH privates — is wiped. */
object DoubleRatchet:
  import aead.Aead
  import x25519.X25519

  // Wire budget inside the immovable 256-byte store frame (dh-ratchet.md §6):
  //   nonce(12) ‖ AEAD(HK, header)(56) ‖ AEAD(MK, inner)(188)
  // ONE random frame nonce is shared by both AEADs — safe because HK and MK are independent keys
  // (ChaCha20-Poly1305's nonce-uniqueness requirement is per-key). The "derive header nonce from Ns"
  // sketch in an early draft was circular (Ns lives INSIDE the encrypted header), so a stored random
  // nonce is used; over a sending chain HK sees random 96-bit nonces, whose birthday-collision bound
  // is negligible for any realistic chain length (and MK is unique per message regardless).
  private val DhBytes: Int = X25519.KeyBytes // 32
  private val CtrBytes: Int = 4 // PN, Ns as 4-byte big-endian (a chain resets Ns to 0 each DH step)
  private val HeaderPlain: Int = DhBytes + 2 * CtrBytes // 40
  private val Nonce: Int = Aead.NonceBytes // 12
  private val Tag: Int = Aead.TagBytes // 16
  private val SealedHeader: Int = HeaderPlain + Tag // 56
  val WireSize: Int = frame.Frame.Size // 256
  /** The plaintext inner block the ratchet seals per message (what `sendMessage` pads into) — 172 B.
    *
    * '''NOT the app payload.''' The live path always carries the 16-byte ARQ header, so the message
    * region is `ArqFrame.PayloadBytes` (156) and the app payload is
    * `Frame.maxPayload(ArqFrame.PayloadBytes)` = '''154'''. Chunked objects get less again:
    * `ChunkStream.ChunkCapacity` = '''145'''. (170 = `maxPayload(172)` is the PRE-ARQ figure; no
    * live path delivers it, so it is not pinned.) 256/172/156/154/145 are all asserted in
    * `ChunkStreamCrossSpec`. */
  val InnerSize: Int = WireSize - Nonce - SealedHeader - Tag // 172
  private val HeaderOffset: Int = Nonce // 12
  private val MsgOffset: Int = Nonce + SealedHeader // 68

  /** Out-of-order tolerance: at most this many message keys are skipped+stashed per chain step, and
    * at most this many stashed total (oldest evicted + wiped). A header claiming a larger jump is
    * rejected as a carrier — no memory blow-up, no distinguishable error (dh-ratchet.md §7). */
  val MaxSkip: Int = 1000
  private val MaxSkipStore: Int = 2000

  // ---- KDFs (HMAC-SHA256 only, vetted `kdf.Kdf` seam) — dh-ratchet.md §4 -----------------------

  /** Root KDF: advance the root key and derive a new chain key + next header key from a DH output. */
  private def kdfRk(rk: Array[Byte], dh: Array[Byte]): (Array[Byte], Array[Byte], Array[Byte]) =
    val prk = kdf.Kdf.hmacSha256(rk, "dr/rk".getBytes(UTF_8) ++ dh)
    val rk2 = kdf.Kdf.hmacSha256(prk, "dr/root".getBytes(UTF_8))
    val ck = kdf.Kdf.hmacSha256(prk, "dr/chain".getBytes(UTF_8))
    val nhk = kdf.Kdf.hmacSha256(prk, "dr/hdr".getBytes(UTF_8))
    wipe(prk)
    (rk2, ck, nhk)

  /** Message key at the current chain position (the old chain key is NOT advanced here). */
  private def messageKey(ck: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(ck, "dr/msg".getBytes(UTF_8))

  /** The next chain key — the one-way symmetric ratchet step (caller wipes the old chain key). */
  private def nextCk(ck: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(ck, "dr/next".getBytes(UTF_8))

  private def wipe(a: Array[Byte]): Unit =
    var i = 0
    while i < a.length do
      a(i) = 0.toByte
      i += 1

  private def enc4(n: Int): Array[Byte] =
    Array(
      ((n >> 24) & 0xff).toByte,
      ((n >> 16) & 0xff).toByte,
      ((n >> 8) & 0xff).toByte,
      (n & 0xff).toByte
    )
  private def dec4(b: Array[Byte], off: Int): Int =
    ((b(off) & 0xff) << 24) | ((b(off + 1) & 0xff) << 16) | ((b(off + 2) & 0xff) << 8) | (b(
      off + 3
    ) & 0xff)

  // ---- Bootstrap (dh-ratchet.md §5): both sides derive a deterministic responder ratchet key + the
  //      root and the two shared header keys from the handshake `contentRoot`; no interactive prekey.
  //      PCS healing comes from the FIRST random DH step (initiator on send, responder on receive).

  private def bootstrap(
      contentRoot: Array[Byte]
  ): (Array[Byte], Array[Byte], Array[Byte], Array[Byte]) =
    val dhSeed = kdf.Kdf.hmacSha256(contentRoot, "dr/bootstrap-ratchet".getBytes(UTF_8))
    val rk0 = kdf.Kdf.hmacSha256(contentRoot, "dr/root0".getBytes(UTF_8))
    val hka =
      kdf.Kdf.hmacSha256(contentRoot, "dr/hdr/a".getBytes(UTF_8)) // initiator's first send HK
    val nhkb = kdf.Kdf.hmacSha256(contentRoot, "dr/hdr/b".getBytes(UTF_8)) // responder's next HK
    (dhSeed, rk0, hka, nhkb)

  /** Initiator ("Alice"): can send immediately — performs the first DH step against the responder's
    * deterministic bootstrap public key, mixing in a fresh random DH secret. */
  def initInitiator(contentRoot: Array[Byte]): DoubleRatchet =
    val (dhSeed, rk0, hka, nhkb) = bootstrap(contentRoot)
    val bobPub = X25519.publicKey(dhSeed)
    wipe(dhSeed)
    val (priv, pub) = X25519.generateKeyPair()
    val dh = X25519.sharedSecret(priv, bobPub)
    val (rk, cks, nhks) = kdfRk(rk0, dh)
    wipe(dh)
    wipe(rk0)
    new DoubleRatchet(
      dhsPriv = priv,
      dhsPub = pub,
      dhr = Some(bobPub),
      rk = rk,
      cks = Some(cks),
      ckr = None,
      hks = Some(hka),
      hkr = None,
      nhks = nhks,
      nhkr = nhkb,
      // One `kdfRk` has already run above (rk0 → rk), so this side starts at root index 1 — the
      // responder starts at 0 holding rk0. Both traverse the SAME root chain (see `rootIndex`).
      rootIdx0 = 1
    )

  /** Responder ("Bob"): holds the deterministic bootstrap key pair and CANNOT send until it has
    * received the initiator's first message (which establishes its receiving chain and, via the DH
    * step, its sending chain). This "initiator sends first" is inherent to the double ratchet
    * (dh-ratchet.md §5); the engine holds a responder's queued messages until then. */
  def initResponder(contentRoot: Array[Byte]): DoubleRatchet =
    val (dhSeed, rk0, hka, nhkb) = bootstrap(contentRoot)
    val bobPub = X25519.publicKey(dhSeed)
    new DoubleRatchet(
      dhsPriv = dhSeed,
      dhsPub = bobPub,
      dhr = None,
      rk = rk0,
      cks = None,
      ckr = None,
      hks = None,
      hkr = None,
      nhks = nhkb,
      nhkr = hka,
      rootIdx0 = 0 // holds rk0 itself — the root chain's origin (see `rootIndex`)
    )

/** A live double-ratchet session for ONE buddy. Single-threaded by contract (one engine per client).
  * Construct via `DoubleRatchet.initInitiator` / `initResponder`. */
final class DoubleRatchet private (
    private var dhsPriv: Array[Byte], // our current ratchet private key
    private var dhsPub: Array[Byte], // our current ratchet public key
    private var dhr: Option[Array[Byte]], // peer's current ratchet public key
    private var rk: Array[Byte], // root key
    private var cks: Option[Array[Byte]], // sending chain key
    private var ckr: Option[Array[Byte]], // receiving chain key
    private var hks: Option[Array[Byte]], // sending header key
    private var hkr: Option[Array[Byte]], // receiving header key
    private var nhks: Array[Byte], // next sending header key (always defined)
    private var nhkr: Array[Byte], // next receiving header key (always defined)
    rootIdx0: Int // this side's starting position on the shared root chain (see `rootIndex`)
):
  import DoubleRatchet.*
  import aead.Aead
  import x25519.X25519

  private var ns: Int = 0 // message number in the current sending chain
  private var nr: Int = 0 // message number in the current receiving chain
  private var pn: Int = 0 // length of the previous sending chain
  // Skipped message keys for out-of-order / missed frames, grouped by receiving-chain epoch. The
  // header key is held as a WIPEABLE byte array (not a hex String, which the JVM cannot zero), so a
  // retired header key leaves no un-erasable copy behind — same metadata-unlinkability concern that
  // motivates wiping retired header keys in `dhRatchet`. Insertion-ordered (oldest evicted first).
  private final class SkippedEpoch(val hk: Array[Byte]):
    val keys = mutable.LinkedHashMap.empty[Int, Array[Byte]] // N -> message key
  private val skippedEpochs = mutable.ArrayBuffer.empty[SkippedEpoch]
  private var skippedCount = 0 // total stashed keys across all epochs (bounded by MaxSkipStore)

  // ---- Continuous-PQ epoch fold (design/continuous-pq-ratchet.md §4, §7 Phase 3) ---------------
  //
  // WHY AN INDEX. The two peers traverse ONE shared root chain rk0, rk1, rk2, … — every root is
  // `kdfRk(rk_{i-1}, dh_i)` over a DH output BOTH sides compute — but they traverse it at DIFFERENT
  // times and are never simultaneously at the same root: `dhRatchet` advances the root by two per
  // step, so one side sits on the odd roots and the other on the even ones, alternating the lead.
  // "Fold the current root" is therefore NOT a shared instruction. The only well-defined shared
  // anchor is a root INDEX, which both sides pass through (some indices only transiently, mid-
  // `dhRatchet`). So the fold is armed for an index and applied by `advanceRoot` exactly when the
  // chain reaches it — identically on both sides, giving the byte-identical `RK_epoch` §4.2 demands.
  //
  // WHAT ARMING IS NOT. Arming is NOT the confirmation gate: `Engine` constant-time verifies the
  // peer's per-direction `EpochKdf.epochConfirmTag*` BEFORE it ever calls `armEpochFold`, so no
  // ratchet state moves on an unconfirmed epoch secret (§4.2 fail-closed). `armEpochFold` itself
  // fails closed on an index the chain has already passed (an un-appliable fold), mutating nothing.
  private final class PendingFold(val anchor: Int, val ss: Array[Byte])
  private var pendingFold: Option[PendingFold] = None
  private var rootIdx: Int = rootIdx0
  private var foldsApplied: Int = 0

  /** This side's position on the SHARED root chain (see above). PUBLIC metadata: it counts DH steps,
    * is derivable from the frames the peer has seen, and reveals nothing about any key. */
  def rootIndex: Int = rootIdx

  /** How many epoch folds this ratchet has committed — observability for the engine + tests. */
  def epochFoldsApplied: Int = foldsApplied

  /** True while a fold is armed but not yet reached (its anchor is still ahead on the chain). */
  def epochFoldArmed: Boolean = pendingFold.isDefined

  /** Arm the epoch fold `RK ← EpochKdf.kdfEpoch(RK, ss)` at root index `anchor` (design §4.1/§4.2).
    *
    * `anchor == rootIndex` applies it NOW (the receiver of an `EPOCH_COMMIT`: after processing that
    * frame it sits exactly on the committer's anchor); `anchor > rootIndex` defers it to
    * [[advanceRoot]] (the committer: it arms its own NEXT index and reaches it on its next DH step).
    * `anchor < rootIndex` is un-appliable — the chain has passed it — so it FAILS CLOSED: returns
    * `false`, mutates nothing, and retains no copy of `ss` (the caller wipes its own).
    *
    * Takes a private CLONE of `ss` so the caller's wipe cannot blank an armed fold, and wipes that
    * clone the moment the fold commits (or is disarmed) — §4.4's "wipe on completion / abort". */
  def armEpochFold(anchor: Int, ss: Array[Byte]): Boolean =
    require(ss.length == EpochKdf.KeyBytes, s"epoch secret ${ss.length} != ${EpochKdf.KeyBytes}")
    if anchor < rootIdx || pendingFold.isDefined then false
    else
      pendingFold = Some(new PendingFold(anchor, ss.clone()))
      applyPendingFold() // anchor == rootIdx ⇒ fold now
      true

  /** Drop an armed-but-unapplied fold, wiping its epoch-secret clone (abort / timeout / teardown,
    * §4.4). Safe to call unconditionally; a fold already COMMITTED is not undone (a completed fold's
    * hardening is never stripped — design §8.2 "Aborted → PqEpoch"). */
  def disarmEpochFold(): Unit =
    pendingFold.foreach(f => wipe(f.ss))
    pendingFold = None

  /** Commit the armed fold iff the chain has just reached its anchor. ATOMIC, mirroring `decrypt`'s
    * scratch-compute / commit-on-verify discipline: `EpochKdf.kdfEpoch` runs to completion on a
    * SCRATCH array first, and only a fully-derived `RK_epoch` replaces the live root — the old root
    * and the epoch secret are wiped only after that swap, so no path can leave a half-folded root.
    * The branch is on a public counter, never on key material (Constitution II). */
  private def applyPendingFold(): Unit =
    pendingFold match
      case Some(f) if f.anchor == rootIdx =>
        val folded = EpochKdf.kdfEpoch(rk, f.ss) // scratch — no instance state touched yet
        wipe(rk) // the pre-fold root is retired: it must not survive the fold (Constitution II)
        rk = folded
        wipe(f.ss)
        pendingFold = None
        foldsApplied += 1
      case _ => ()

  /** The ONLY path that advances the shared root chain: retire the old root, take `newRk` as root
    * `rootIndex + 1`, and apply an epoch fold armed for that index. Every `kdfRk` result in
    * `dhRatchet` flows through here, so an armed anchor can never be silently skipped. */
  private def advanceRoot(newRk: Array[Byte]): Unit =
    wipe(rk)
    rk = newRk
    rootIdx += 1
    applyPendingFold()

  /** True once a sending chain exists (the initiator from the start; the responder after its first
    * received message). The engine must not call `encrypt` / `encryptPending` while this is false. */
  def canSend: Boolean = cks.isDefined && hks.isDefined

  /** Our current ratchet public key — exposed for tests/diagnostics only (it is PUBLIC). */
  def sendingPublicKey: Array[Byte] = dhsPub.clone()

  // ---- Send ------------------------------------------------------------------------------------

  /** Build the 256-byte wire frame for `inner` at the CURRENT sending position WITHOUT advancing —
    * so a failed transport submit can retry at the same chain position (mirrors the engine's existing
    * peek/commit split). A fresh nonce is drawn per call. */
  def encryptPending(inner: Array[Byte]): Array[Byte] =
    require(inner.length == InnerSize, s"inner ${inner.length} != $InnerSize")
    val ck = cks.getOrElse(
      throw new IllegalStateException("no sending chain yet (responder must receive first)")
    )
    val headerKey = hks.getOrElse(throw new IllegalStateException("no sending header key yet"))
    val mk = messageKey(ck)
    val header = dhsPub ++ enc4(pn) ++ enc4(ns)
    val nonce = random.Rand.bytes(Nonce)
    val sealedHeader = Aead.seal(headerKey, nonce, header)
    val sealedMsg = Aead.seal(mk, nonce, inner)
    wipe(mk)
    nonce ++ sealedHeader ++ sealedMsg

  /** Commit a send: ratchet the sending chain forward (wiping the old key) and bump `Ns`. Call only
    * after the corresponding `encryptPending` frame was actually accepted by the transport. */
  def commitSend(): Unit =
    val ck = cks.getOrElse(throw new IllegalStateException("no sending chain to commit"))
    cks = Some(nextCk(ck))
    wipe(ck)
    ns += 1

  /** Encrypt + advance in one step (Signal-style). Used by tests; the engine uses the peek/commit
    * pair so a transport failure does not consume a chain position. */
  def encrypt(inner: Array[Byte]): Array[Byte] =
    val wire = encryptPending(inner)
    commitSend()
    wire

  // ---- Receive ---------------------------------------------------------------------------------

  /** Decrypt a 256-byte wire frame to its inner block, advancing the ratchet (DH step + skipped-key
    * handling as needed). Returns `None` — WITHOUT mutating ratchet state — for a malformed frame, a
    * header that matches neither header key (a carrier or a frame for someone else), or a jump beyond
    * `MaxSkip`. So an undecryptable frame is indistinguishable from a carrier (dh-ratchet.md §6/§9). */
  def decrypt(wire: Array[Byte]): Option[Array[Byte]] =
    if wire.length != WireSize then None
    else
      val nonce = wire.slice(0, Nonce)
      val sealedHeader = wire.slice(HeaderOffset, HeaderOffset + SealedHeader)
      val sealedMsg = wire.slice(MsgOffset, WireSize)
      trySkipped(nonce, sealedHeader, sealedMsg).orElse:
        decryptHeader(nonce, sealedHeader) match
          case None => None // matches no header key ⇒ carrier / not ours: no state change
          case Some((dhPub, headerPn, headerN, isDhStep)) =>
            // Bound-check BEFORE any mutation so an over-large jump aborts cleanly as a carrier.
            val ok =
              if isDhStep then withinSkip(nr, headerPn) && headerN >= 0 && headerN <= MaxSkip
              else withinSkip(nr, headerN)
            if !ok then None
            else
              // ATOMIC receive: the sealed header and sealed message are authenticated under
              // INDEPENDENT keys, so a valid header with a tampered body would otherwise advance the
              // ratchet (DH step, skips, wipes) and only THEN fail the message AEAD — letting an active
              // attacker consume a ratchet position with a single bit flip. So we first derive this
              // frame's message key on a SCRATCH copy of the state (no instance mutation) and open the
              // body; only on success do we replay the real mutations. A failure leaves the ratchet
              // untouched (the no-mutation-on-undecryptable invariant, dh-ratchet.md §6/§9).
              // A DH-step peek runs the ECDH against the header's ratchet key, which is PUBLIC and
              // attacker-supplied; a low-order / non-canonical peer key makes X25519.sharedSecret
              // throw `PeerKeyRejected` uniformly on both platforms. Treat that like any other
              // undecryptable frame — drop it, no state mutation (peekMessageKey mutates nothing). We
              // catch EXACTLY `PeerKeyRejected` (not any IllegalArgumentException) so an unrelated
              // IllegalArgumentException from a genuine bug — e.g. corrupted key material reaching the
              // KDF inside peekMessageKey — is NOT silently swallowed as a carrier. The branch is
              // governed by the public peer key, not by any secret, so no secret-dependent timing is
              // introduced (dh-ratchet.md §6/§9).
              val mkOpt =
                try Some(peekMessageKey(dhPub, headerN, isDhStep))
                catch case _: x25519.PeerKeyRejected => None
              mkOpt match
                case None => None // rejected peer ratchet key ⇒ carrier / not ours: no state change
                case Some(mk) =>
                  Aead.open(mk, nonce, sealedMsg) match
                    case None =>
                      wipe(mk)
                      None
                    case Some(inner) =>
                      wipe(mk)
                      if isDhStep then
                        skipMessageKeys(
                          headerPn
                        ) // finish the previous chain (stash, under the OLD HKr)
                        dhRatchet(dhPub)
                      skipMessageKeys(headerN) // skip up to this frame in the current chain
                      val ck = ckr.get
                      ckr = Some(nextCk(ck))
                      wipe(ck)
                      nr += 1
                      Some(inner)

  /** Derive THIS frame's message key without mutating instance state — used to verify the message
    * AEAD before committing the ratchet mutations (see `decrypt`). Walks a scratch chain key forward;
    * for a DH step it derives the would-be new receiving chain purely (no fresh sending key, no wipes
    * of live state). */
  private def peekMessageKey(dhPub: Array[Byte], headerN: Int, isDhStep: Boolean): Array[Byte] =
    var ck =
      if isDhStep then
        val dh = X25519.sharedSecret(dhsPriv, dhPub)
        val (rkTmp, ckrNew, nhkTmp) = kdfRk(rk, dh)
        wipe(dh) // the peeked DH output is a secret too — don't leave it on the heap
        wipe(rkTmp)
        wipe(nhkTmp)
        ckrNew // a fresh array — safe to wipe during the walk below
      else ckr.get.clone() // clone so the walk does not wipe the live receiving chain key
    var i = if isDhStep then 0 else nr
    while i < headerN do
      val nx = nextCk(ck)
      wipe(ck)
      ck = nx
      i += 1
    val mk = messageKey(ck)
    wipe(ck)
    mk

  /** Try the stashed out-of-order keys: for each stored receiving-chain epoch, trial-open the header
    * with that epoch's header key; on a match, look up `N` and decrypt. Atomic, like the main receive
    * path: open the body FIRST and only remove + wipe the stashed key on success — so a valid header
    * with a tampered body cannot consume a stashed ratchet position (the genuine frame still decrypts
    * later). */
  private def trySkipped(
      nonce: Array[Byte],
      sealedHeader: Array[Byte],
      sealedMsg: Array[Byte]
  ): Option[Array[Byte]] =
    skippedEpochs.iterator
      .flatMap(ep =>
        Aead.open(ep.hk, nonce, sealedHeader).map(h => (ep, dec4(h, DhBytes + CtrBytes)))
      )
      .collectFirst { case (ep, n) if ep.keys.contains(n) => (ep, n) }
      .flatMap { case (ep, n) =>
        Aead.open(ep.keys(n), nonce, sealedMsg) match
          case None => None // tampered body ⇒ leave the stash intact (no position consumed)
          case Some(inner) =>
            wipe(ep.keys.remove(n).get)
            skippedCount -= 1
            if ep.keys.isEmpty then // epoch drained: wipe its header key and drop it
              wipe(ep.hk)
              skippedEpochs -= ep
            Some(inner)
      }

  /** Trial-decrypt the header: current HKr ⇒ (…, isDhStep=false); else next HKr ⇒ DH step. */
  private def decryptHeader(
      nonce: Array[Byte],
      sealedHeader: Array[Byte]
  ): Option[(Array[Byte], Int, Int, Boolean)] =
    def parse(h: Array[Byte], dhStep: Boolean) =
      (h.slice(0, DhBytes), dec4(h, DhBytes), dec4(h, DhBytes + CtrBytes), dhStep)
    hkr
      .flatMap(hk => Aead.open(hk, nonce, sealedHeader))
      .map(parse(_, false))
      .orElse(Aead.open(nhkr, nonce, sealedHeader).map(parse(_, true)))

  /** A forward skip of `until - nr` is allowed only if non-negative and within `MaxSkip`. */
  private def withinSkip(from: Int, until: Int): Boolean =
    until >= from && (until - from) <= MaxSkip

  /** Advance the receiving chain up to `until`, stashing each intermediate message key under the
    * current receiving header key so an out-of-order frame can still be decrypted. No-op when there
    * is no receiving chain yet (the bound check guarantees `until == nr` in that case). */
  private def skipMessageKeys(until: Int): Unit =
    ckr match
      case None => ()
      case Some(_) =>
        // All keys skipped here belong to the current receiving epoch (one header key); find or open
        // its stash bucket once.
        val hk = hkr.get
        val epoch = skippedEpochs.find(e => java.util.Arrays.equals(e.hk, hk)).getOrElse {
          val e = new SkippedEpoch(hk.clone()); skippedEpochs += e; e
        }
        while nr < until do
          val ck = ckr.get
          epoch.keys(nr) = messageKey(ck)
          skippedCount += 1
          evictIfOverCap()
          ckr = Some(nextCk(ck))
          wipe(ck)
          nr += 1

  /** Bound the stash (DoS-resistant): evict + wipe the oldest stashed message key, dropping (and
    * wiping) an epoch once it is drained, until the total is within `MaxSkipStore`. */
  private def evictIfOverCap(): Unit =
    while skippedCount > MaxSkipStore && skippedEpochs.nonEmpty do
      val oldest = skippedEpochs.head
      val (n, mk) = oldest.keys.head
      oldest.keys.remove(n)
      wipe(mk)
      skippedCount -= 1
      if oldest.keys.isEmpty then
        wipe(oldest.hk)
        skippedEpochs.remove(0)

  /** A DH ratchet step: rotate header keys, derive the receiving chain from the peer's new public
    * key, then generate a FRESH random sending key pair and derive the new sending chain — this is
    * where post-compromise healing happens (dh-ratchet.md §4/§8). */
  private def dhRatchet(peerPub: Array[Byte]): Unit =
    pn = ns
    ns = 0
    nr = 0
    // Rotate header keys, wiping the retired ones: a stale header key captured later would let an
    // attacker LINK this chain's past frames — the metadata leak header encryption exists to prevent.
    // (Skipped-key epochs hold their OWN cloned header-key copy, so they are unaffected by this wipe.)
    val retiredHks = hks
    val retiredHkr = hkr
    hks = Some(nhks)
    hkr = Some(nhkr)
    retiredHks.foreach(wipe)
    retiredHkr.foreach(wipe)
    dhr = Some(peerPub)
    val dhRecv = X25519.sharedSecret(dhsPriv, peerPub)
    val (rk1, ckrNew, nhkrNew) = kdfRk(rk, dhRecv)
    wipe(dhRecv)
    // Both new roots go through `advanceRoot`, which retires the old root AND applies an epoch fold
    // armed for the index just reached. The mid-step root (rk1) is a real, shared chain position —
    // the peer holds it PERSISTENTLY while we only pass through it — so it must be foldable here or
    // the two sides would fold at different positions and diverge (see the `rootIndex` note).
    advanceRoot(rk1)
    ckr = Some(ckrNew)
    nhkr = nhkrNew
    val (newPriv, newPub) = X25519.generateKeyPair()
    val dhSend = X25519.sharedSecret(newPriv, peerPub)
    val (rk2, cksNew, nhksNew) = kdfRk(rk, dhSend)
    wipe(dhSend)
    advanceRoot(rk2)
    wipe(dhsPriv)
    dhsPriv = newPriv
    dhsPub = newPub
    cks = Some(cksNew)
    nhks = nhksNew
