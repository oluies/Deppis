package engine

import java.nio.charset.StandardCharsets.UTF_8

/** Epoch-fold KDF + per-direction confirmation tags for the CONTINUOUS post-quantum ratchet —
  * **Phase 1 building block only** (design/continuous-pq-ratchet.md §4, §7 Phase 1).
  *
  * ==Honest scope (Constitution IV)==
  * This module is PURE and is NOT wired into the live ratchet: `DoubleRatchet` does not call it,
  * nothing on the wire changes, and no privacy or PQ claim changes. It becomes load-bearing only
  * in Phase 3, when the periodic-rekey state machine folds a fresh hybrid-KEM (X25519+ML-KEM-768)
  * epoch secret into the live root at the epoch-commit anchor. Until then the live content ratchet
  * heals classically (X25519 only), as documented in `KeySchedule.pqContentRoot`'s honesty note.
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
  * `KeySchedule.pqConfirmTagInitiator`/`pqConfirmTagResponder`). The tags also mix the folded root
  * under labels no ratchet key consumes, so publishing them reveals nothing about the root (HMAC
  * one-wayness).
  *
  * ==Why confirmation tags at all==
  * ML-KEM uses IMPLICIT REJECTION: `decaps` never throws on a tampered same-length ciphertext, it
  * silently returns a pseudo-random secret. Without explicit key confirmation before the fold
  * commits, a tampered KEM chunk would silently fork the ratchet into a "confirmed but dead" state
  * that ALSO strips the PQ hardening (design §4.2). Phase 3 must compute `kdfEpoch` on SCRATCH
  * state, exchange these per-direction tags, constant-time verify the peer's tag, and only then
  * commit `RK_epoch` (and wipe the old `RK`) — mirroring `DoubleRatchet.decrypt`'s scratch-compute
  * / commit-on-verify discipline.
  *
  * ==Wipe contract (Constitution II)==
  * Callers wipe the inputs (`rk`, `ss`, `rkEpoch`) — this module never retains or wipes ITS
  * arguments. It DOES wipe every secret-bearing intermediate it allocates (the HMAC info
  * concatenation), so no un-wiped copy of the KEM shared secret survives this call. No
  * secret-dependent branches: the only branches are the public length `require`s.
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

  /** The INITIATOR's epoch key-confirmation tag over the scratch folded root — label
    * `"dr/pq-epoch-confirm/i"` (design §4.2). The responder constant-time verifies it before
    * committing `RK_epoch`; see [[epochConfirmTagResponder]] for the mirror direction. Publishing
    * the tag reveals nothing about the root (distinct label + HMAC one-wayness). */
  def epochConfirmTagInitiator(rkEpoch: Array[Byte]): Array[Byte] =
    require(rkEpoch.length == KeyBytes, s"rkEpoch must be $KeyBytes bytes, got ${rkEpoch.length}")
    kdf.Kdf.hmacSha256(rkEpoch, "dr/pq-epoch-confirm/i".getBytes(UTF_8))

  /** The RESPONDER's epoch key-confirmation tag — label `"dr/pq-epoch-confirm/r"` (design §4.2).
    * Domain-separated from the initiator's `/i` tag so a tag seen on the wire in one direction can
    * never be reflected back to satisfy the other direction's check. */
  def epochConfirmTagResponder(rkEpoch: Array[Byte]): Array[Byte] =
    require(rkEpoch.length == KeyBytes, s"rkEpoch must be $KeyBytes bytes, got ${rkEpoch.length}")
    kdf.Kdf.hmacSha256(rkEpoch, "dr/pq-epoch-confirm/r".getBytes(UTF_8))
