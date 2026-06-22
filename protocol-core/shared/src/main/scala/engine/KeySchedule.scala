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

  /** Initial chain key for the `from → to` direction; both parties derive the same one. */
  def chain0(contentRoot: Array[Byte], from: String, to: String): Array[Byte] =
    kdf.Kdf.hmacSha256(contentRoot, s"ks/chain/$from/$to".getBytes(UTF_8))

  /** The AEAD message key at the current chain position (32 bytes = `aead.Aead.KeyBytes`). */
  def messageKey(chainKey: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(chainKey, "ks/msg-key".getBytes(UTF_8))

  /** The next chain key — the one-way ratchet step (the old chain key must be wiped after). */
  def nextChain(chainKey: Array[Byte]): Array[Byte] =
    kdf.Kdf.hmacSha256(chainKey, "ks/chain-key".getBytes(UTF_8))
