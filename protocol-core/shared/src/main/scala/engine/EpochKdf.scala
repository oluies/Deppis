package engine

import java.nio.charset.StandardCharsets.UTF_8

/** Epoch-fold KDF + per-direction confirmation tags for the CONTINUOUS post-quantum ratchet
  * (design/continuous-pq-ratchet.md §4). Introduced in Phase 1 as a pure building block; wired into
  * the live ratchet by Phase 3 (§7).
  *
  * ==Honest scope (Constitution IV)==
  * This module is PURE. As of Phase 3 it IS load-bearing: `DoubleRatchet.armEpochFold` folds a fresh
  * hybrid-KEM (X25519+ML-KEM-768) epoch secret into the live root at the epoch-commit anchor, and
  * `Engine`'s rekey state machine keys the confirmation tags below. Nothing on the wire changed (the
  * 256-byte frame is untouched) and NO PRIVACY OR PQ CLAIM CHANGED: the labeling gate is Phase 5's
  * formal analysis (the `pq_post_compromise_security` model under a breaks-CDH-but-not-ML-KEM
  * attacker), so `DEV, NO METADATA PRIVACY` stands regardless of how many epochs fold.
  *
  * ==What the fold is==
  * `kdfEpoch(rk, ss) = HMAC(rk, "dr/pq-epoch" ‖ ss)` — the RATCHET-EPOCH analogue of the
  * pairing-time `KeySchedule.pqContentRoot` (`HMAC(contentRoot, "ks/pq-prekey" ‖ ss)`), applied to
  * the LIVE root `RK` once per epoch: `RK ← kdfEpoch(RK, ss)`, then the next `dhRatchet`/`kdfRk`
  * proceeds from the PQ-hardened root as normal. Hybrid composition (design §4.3): `RK` carries all
  * prior classical X25519 entropy and `ss` carries the ML-KEM arm, so the folded root is
  * `≥ max(classical, PQ)` — a broken KEM never weakens today's classical ratchet, and a CRQC that
  * captured a pre-fold root still cannot compute any post-fold root without the ML-KEM secret.
  *
  * ==Domain separation==
  * The `"dr/pq-epoch"` label is NEW and distinct from every other HMAC label in the schedule
  * (`"ks/pq-prekey"`, `"dr/rk"`, `"dr/root"`, …), so an epoch fold can never collide with a pairing
  * fold or a per-step root derivation. The two confirmation-tag labels differ per DIRECTION
  * (`"dr/pq-epoch-confirm/i"` vs `"…/r"`), so a tag observed in transit for one direction can never
  * satisfy the other direction's constant-time check (anti-reflection — same defense as
  * `KeySchedule.pqConfirmTagInitiator`/`pqConfirmTagResponder`). The tag labels are also distinct
  * from `"dr/pq-epoch"`, so a published tag is an HMAC of the epoch secret under a label no key in
  * the schedule consumes — it reveals nothing about that secret, and nothing about the fold it
  * authorizes (HMAC one-wayness).
  *
  * ==Why confirmation tags at all==
  * ML-KEM uses IMPLICIT REJECTION: `decaps` never throws on a tampered same-length ciphertext, it
  * silently returns a pseudo-random secret. Without explicit key confirmation before the fold
  * commits, a tampered KEM chunk would silently fork the ratchet into a "confirmed but dead" state
  * that ALSO strips the PQ hardening (design §4.2). So the two sides exchange these per-direction
  * tags and constant-time verify the peer's BEFORE any ratchet state moves.
  *
  * ==What the tags are keyed on: the KEM SHARED SECRET, not `RK_epoch`==
  * Read this before the Phase 5 formal analysis. Design §4.2 (and this module's own Phase 1
  * scaladoc, when it shipped) describes the tags as computed "over the scratch folded root"
  * `RK_epoch`. **Phase 3 keys them on the 32-byte hybrid-KEM shared secret `ss` itself**, and that
  * is deliberate, not drift:
  *
  *   - `RK_epoch` is UNAVAILABLE while the tags are in flight. The fold is anchored to a root INDEX
  *     because the two peers traverse one shared root chain but are never simultaneously on the same
  *     root (`DoubleRatchet.rootIndex`); computing `RK_epoch` needs that anchor root, which neither
  *     side holds until the commit — i.e. until after the tags have done their job.
  *   - Exchanging the tags AFTER the fold instead would reintroduce the exact failure §4.2 exists to
  *     prevent: a mismatched `ss` means the roots have already parted, so the tag frame would not
  *     even decrypt — a silent "confirmed but dead" fork rather than an explicit refusal.
  *   - Keying on `ss` loses nothing the tags are for. `ss` is precisely the value implicit rejection
  *     makes uncertain, so an HMAC under it is exactly the key confirmation required; the
  *     session/transcript binding that keying on `RK_epoch` would have added is already supplied by
  *     the tags travelling inside the pair's authenticated, MK-sealed ratchet chain, and the anchor
  *     binding by the explicit, re-checked `ChunkStream.Envelope.EpochCommit.anchor`.
  *   - Publishing `HMAC(ss, label)` does not weaken the fold. `ss` is one-way-protected by HMAC, and
  *     the fold uses `ss` as DATA under the independent, secret key `RK` — different role, different
  *     key, and the labels are domain-separated from every other in the schedule.
  *
  * The parameter is therefore named `epochSecret`, not `rkEpoch`: the functions are plain
  * domain-separated HMACs over a 32-byte epoch key, and the length `require` cannot tell the two
  * candidate keyings apart (both are 32 bytes), so the NAME is the only guard against re-drifting.
  *
  * ==Wipe contract (Constitution II)==
  * Callers wipe the inputs (`rk`, `ss`) — this module never retains or wipes ITS arguments. It DOES
  * wipe every secret-bearing intermediate it allocates (the HMAC info concatenation), so no un-wiped
  * copy of the KEM shared secret survives this call. No secret-dependent branches: the only branches
  * are the public length `require`s.
  *
  * HMAC-SHA256 only, composed from the vetted cross-platform `kdf.Kdf` seam (JVM + Scala.js) —
  * Constitution I; no new primitive. */
object EpochKdf:
  /** Bytes of the root key and the hybrid-KEM shared secret (both fixed-size 32-byte values:
    * HMAC-SHA256 output and `kem.HybridKem.SharedSecretBytes`). */
  val KeyBytes: Int = 32

  /** Fold a hybrid-KEM epoch shared secret into the live ratchet root:
    * `RK_epoch = HMAC(rk, "dr/pq-epoch" ‖ kemSharedSecret)` (design §4.1).
    *
    * Pure and total on valid input; both sides call it with byte-identical `(rk, ss)` at the
    * deterministic epoch-commit anchor and derive the byte-identical `RK_epoch`. The caller wipes
    * `rk` (after commit) and `kemSharedSecret`; the info concatenation built here is wiped in
    * `finally` — a bare `label ++ kemSharedSecret` would leave an intermediate array holding an
    * un-wiped copy of the KEM shared secret (Constitution II). */
  def kdfEpoch(rk: Array[Byte], kemSharedSecret: Array[Byte]): Array[Byte] =
    require(rk.length == KeyBytes, s"rk must be $KeyBytes bytes, got ${rk.length}")
    require(
      kemSharedSecret.length == KeyBytes,
      s"kemSharedSecret must be $KeyBytes bytes, got ${kemSharedSecret.length}"
    )
    val label = "dr/pq-epoch".getBytes(UTF_8)
    val info = new Array[Byte](label.length + kemSharedSecret.length)
    System.arraycopy(label, 0, info, 0, label.length)
    System.arraycopy(kemSharedSecret, 0, info, label.length, kemSharedSecret.length)
    try kdf.Kdf.hmacSha256(rk, info)
    finally java.util.Arrays.fill(info, 0.toByte)

  /** The INITIATOR's epoch key-confirmation tag — `HMAC(epochSecret, "dr/pq-epoch-confirm/i")`
    * (design §4.2). `epochSecret` is the 32-byte hybrid-KEM epoch shared secret `ss`, NOT the folded
    * root — see the object doc for why that is the right keying and why the root is unavailable at
    * this point. The responder constant-time verifies this before the epoch may commit; see
    * [[epochConfirmTagResponder]] for the mirror direction. Publishing the tag reveals nothing about
    * `epochSecret` (distinct label + HMAC one-wayness). */
  def epochConfirmTagInitiator(epochSecret: Array[Byte]): Array[Byte] =
    require(
      epochSecret.length == KeyBytes,
      s"epochSecret must be $KeyBytes bytes, got ${epochSecret.length}"
    )
    kdf.Kdf.hmacSha256(epochSecret, "dr/pq-epoch-confirm/i".getBytes(UTF_8))

  /** The RESPONDER's epoch key-confirmation tag — `HMAC(epochSecret, "dr/pq-epoch-confirm/r")`
    * (design §4.2). Domain-separated from the initiator's `/i` tag so a tag seen on the wire in one
    * direction can never be reflected back to satisfy the other direction's check. */
  def epochConfirmTagResponder(epochSecret: Array[Byte]): Array[Byte] =
    require(
      epochSecret.length == KeyBytes,
      s"epochSecret must be $KeyBytes bytes, got ${epochSecret.length}"
    )
    kdf.Kdf.hmacSha256(epochSecret, "dr/pq-epoch-confirm/r".getBytes(UTF_8))
