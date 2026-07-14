package engine

import java.nio.charset.StandardCharsets.UTF_8

/** Per-buddy key schedule — the **forward-secret symmetric ratchet** for the message path.
  *
  * From the handshake `pairKey` we derive two independent roots and then discard `pairKey`:
  *
  *   - `addrKey` (RETAINED) roots the PUBLIC addressing layer — the retrieval tokens and the notify
  *     bit. These are metadata the store/notify observe anyway (and are already single-use /
  *     non-recurrent), so they are deliberately NOT forward-secret.
  *   - `contentRoot` (WIPED right after seeding the chains) roots the per-direction CONTENT chains.
  *     Each message key is `messageKey(chainKey)`; the chain advances `nextChain(chainKey)` and the
  *     old chain key is wiped. Because `pairKey` and `contentRoot` are gone and `addrKey` lives on a
  *     different HMAC branch, no retained value can recompute a past message key — that is the
  *     forward secrecy (a device-state compromise cannot decrypt prior messages).
  *
  * This is the symmetric half of a double ratchet; the DH ratchet (post-compromise security) is a
  * documented follow-up requiring a cross-platform X25519 primitive the repo does not yet have.
  *
  * Single source of truth: the engine ratchets these; the PING-front stand-in and tests reproduce the
  * SAME values from a `pairKey`. HMAC-SHA256 only (vetted `kdf.Kdf` seam; cross-platform JVM + JS —
  * Constitution I). */
object KeySchedule:
  /** The retained addressing root — tokens + notify bit derive from this, never from the raw pairKey. */
  def addrKey(pairKey: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(pairKey, "ks/addr-root".getBytes(UTF_8))

  /** The content-chain root (wiped after the chains are seeded). */
  def contentRoot(pairKey: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(pairKey, "ks/content-root".getBytes(UTF_8))

  /** Fold a hybrid-KEM (X25519+ML-KEM-768) pairing-prekey shared secret into the content root — the
    * **post-quantum pairing prekey** (US7, harvest-now-decrypt-later). The initial content root that
    * seeds the DH double ratchet becomes
    * `HMAC(contentRoot, "ks/pq-prekey" ++ kemSharedSecret)`, so an adversary who has ONLY the
    * (classical) out-of-band pairing secret and later a quantum computer still cannot reconstruct it
    * without also breaking the KEM.
    *
    * HONEST LABELING (Constitution IV): this PQ-protects ONLY the INITIAL content root. The ongoing
    * X25519 DH ratchet (`DoubleRatchet`) that re-keys every message REMAINS CLASSICAL — each per-
    * message DH step is still harvest-now-decrypt-later-exposed. This is NOT post-quantum messaging;
    * it hardens the pairing seed only.
    *
    * Single source of truth: both engine paths (responder `encaps`, initiator `decaps`) and the tests
    * mix through THIS function with the SAME label ordering, so the two sides derive a byte-identical
    * seed. `kemSharedSecret` is a secret — the caller wipes it after this returns. HMAC-SHA256 only
    * (vetted `kdf.Kdf`; cross-platform JVM + JS — Constitution I). */
  def pqContentRoot(contentRoot: Array[Byte], kemSharedSecret: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(contentRoot, "ks/pq-prekey".getBytes(UTF_8) ++ kemSharedSecret)

  /** Key-confirmation tag over the mixed PQ root — the explicit remedy for ML-KEM's IMPLICIT
    * REJECTION. ML-KEM `decaps` never throws on a tampered same-length ciphertext; it silently returns
    * a pseudo-random shared secret. Both sides therefore derive a tag `HMAC(pqRoot, "ks/pq-confirm")`
    * from the mixed root (which depends on the KEM shared secret), and the initiator constant-time
    * compares its tag to the responder's BEFORE seeding. ANY tamper of `kemPublicKey`/`kemCiphertext`
    * changes the shared secret ⇒ changes the root ⇒ changes the tag ⇒ explicit fail-closed, instead of
    * a silently-non-interoperable ("confirmed but dead") pairing that also strips the PQ hardening.
    *
    * Domain-separated from the seed: the tag mixes the SAME root under a DIFFERENT label than any key
    * the ratchet consumes, so publishing the tag reveals nothing about the seed (HMAC one-wayness). */
  def pqConfirmTag(pqContentRoot: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(pqContentRoot, "ks/pq-confirm".getBytes(UTF_8))

  /** Initial chain key for the `from → to` direction; both parties derive the same one. */
  def chain0(contentRoot: Array[Byte], from: String, to: String): Array[Byte] =
    kdf.Kdf.hmacSha256(contentRoot, s"ks/chain/$from/$to".getBytes(UTF_8))

  /** The AEAD message key at the current chain position (32 bytes = `aead.Aead.KeyBytes`). */
  def messageKey(chainKey: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(chainKey, "ks/msg-key".getBytes(UTF_8))

  /** The next chain key — the one-way ratchet step (the old chain key must be wiped after). */
  def nextChain(chainKey: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(chainKey, "ks/chain-key".getBytes(UTF_8))
