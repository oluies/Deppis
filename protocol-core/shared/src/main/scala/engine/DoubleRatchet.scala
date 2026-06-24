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
  /** The plaintext inner block the ratchet seals per message (what `sendMessage` pads into). */
  val InnerSize: Int = WireSize - Nonce - SealedHeader - Tag // 172  ⇒ Frame.maxPayload = 170
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
  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

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
    val (rk, cks, nhks) = kdfRk(rk0, X25519.sharedSecret(priv, bobPub))
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
      nhkr = nhkb
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
      nhkr = hka
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
    private var nhkr: Array[Byte] // next receiving header key (always defined)
):
  import DoubleRatchet.*
  import aead.Aead
  import x25519.X25519

  private var ns: Int = 0 // message number in the current sending chain
  private var nr: Int = 0 // message number in the current receiving chain
  private var pn: Int = 0 // length of the previous sending chain
  // Skipped message keys for out-of-order / missed frames, keyed by (receiving header key, N).
  // Insertion-ordered so the oldest can be evicted (and wiped) when the bound is hit.
  private val skipped = mutable.LinkedHashMap.empty[(String, Int), Array[Byte]]

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
              if isDhStep then
                skipMessageKeys(headerPn) // finish the previous receiving chain (under the OLD HKr)
                dhRatchet(dhPub)
              skipMessageKeys(headerN) // skip up to this frame in the current receiving chain
              val ck = ckr.get
              val mk = messageKey(ck)
              ckr = Some(nextCk(ck))
              wipe(ck)
              nr += 1
              val inner = Aead.open(mk, nonce, sealedMsg)
              wipe(mk)
              inner

  /** Try the stashed out-of-order keys: for each distinct stored receiving header key, trial-open the
    * header; on a match, look up (HK, N) and decrypt + remove + wipe that key. */
  private def trySkipped(
      nonce: Array[Byte],
      sealedHeader: Array[Byte],
      sealedMsg: Array[Byte]
  ): Option[Array[Byte]] =
    val distinctHks = skipped.keysIterator.map(_._1).toSeq.distinct
    distinctHks.iterator
      .flatMap { hkHex =>
        // Recover the raw HK from any entry that carries it (we stored it as the hex key).
        val hkRaw = hexToBytes(hkHex)
        Aead.open(hkRaw, nonce, sealedHeader).map(h => (hkHex, dec4(h, DhBytes + CtrBytes)))
      }
      .collectFirst { case (hkHex, n) if skipped.contains((hkHex, n)) => (hkHex, n) }
      .flatMap { case (hkHex, n) =>
        val mk = skipped.remove((hkHex, n)).get
        val inner = Aead.open(mk, nonce, sealedMsg)
        wipe(mk)
        inner
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
        val hk = hkr.get
        while nr < until do
          val ck = ckr.get
          val mk = messageKey(ck)
          storeSkipped(hk, nr, mk)
          ckr = Some(nextCk(ck))
          wipe(ck)
          nr += 1

  private def storeSkipped(hk: Array[Byte], n: Int, mk: Array[Byte]): Unit =
    skipped((hex(hk), n)) = mk
    while skipped.size > MaxSkipStore do
      val (oldestKey, oldestMk) = skipped.head
      skipped.remove(oldestKey)
      wipe(oldestMk)

  /** A DH ratchet step: rotate header keys, derive the receiving chain from the peer's new public
    * key, then generate a FRESH random sending key pair and derive the new sending chain — this is
    * where post-compromise healing happens (dh-ratchet.md §4/§8). */
  private def dhRatchet(peerPub: Array[Byte]): Unit =
    pn = ns
    ns = 0
    nr = 0
    // Rotate header keys, wiping the retired ones: a stale header key captured later would let an
    // attacker LINK this chain's past frames — the metadata leak header encryption exists to prevent.
    // (Skipped-key entries are keyed by a hex COPY of the header key, so they survive the wipe.)
    val retiredHks = hks
    val retiredHkr = hkr
    hks = Some(nhks)
    hkr = Some(nhkr)
    retiredHks.foreach(wipe)
    retiredHkr.foreach(wipe)
    dhr = Some(peerPub)
    val (rk1, ckrNew, nhkrNew) = kdfRk(rk, X25519.sharedSecret(dhsPriv, peerPub))
    wipe(rk)
    rk = rk1
    ckr = Some(ckrNew)
    nhkr = nhkrNew
    val (newPriv, newPub) = X25519.generateKeyPair()
    val (rk2, cksNew, nhksNew) = kdfRk(rk, X25519.sharedSecret(newPriv, peerPub))
    wipe(rk)
    rk = rk2
    wipe(dhsPriv)
    dhsPriv = newPriv
    dhsPub = newPub
    cks = Some(cksNew)
    nhks = nhksNew

  private def hexToBytes(s: String): Array[Byte] =
    s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
