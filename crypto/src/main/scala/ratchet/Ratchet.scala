package ratchet

import org.signal.libsignal.protocol.{
  IdentityKeyPair,
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress
}
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.{KEMKeyPair, KEMKeyType}
import org.signal.libsignal.protocol.message.{CiphertextMessage, PreKeySignalMessage, SignalMessage}
import org.signal.libsignal.protocol.state.{
  KyberPreKeyRecord,
  PreKeyBundle,
  PreKeyRecord,
  SignedPreKeyRecord
}
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import org.signal.libsignal.protocol.util.KeyHelper

/** Wrapper over the **audited** libsignal double-ratchet (T012, Constitution I — we wrap a vetted
  * implementation and NEVER reimplement the ratchet). Each [[RatchetParty]] is one local identity
  * with its own protocol store; it publishes a prekey bundle (PQXDH), establishes a session from a
  * peer's bundle, and then exchanges messages. Forward secrecy and post-compromise security are
  * provided by the underlying library's double ratchet — this layer only adapts the API to Scala.
  *
  * DEPENDENCY (T012a): the backing crypto is `org.signal:libsignal-client` — Signal's MAINTAINED
  * libsignal (Rust core + Java/JNI bindings), which superseded the archived/EOL pure-JVM
  * `org.whispersystems:signal-protocol-java`. It ships a bundled native library loaded by the JVM at
  * runtime (no separate install; CI exercises the real ratchet on linux/mac). This thin wrapper is
  * the ONLY coupling point, so the migration was localized to this file. We wrap the vetted ratchet
  * and NEVER reimplement it (Constitution I). NOTE: the handshake is PQXDH — as of libsignal 0.8x
  * the Kyber prekey arm is MANDATORY (`PreKeyBundle` has one constructor and it requires the Kyber
  * public key + signature), so the classic X3DH-only bundle this wrapper used to publish is no
  * longer constructible. That is a strengthening, and it is independent of the hybrid ML-KEM work in
  * `protocol-core` — this is Signal's own session handshake, not the Deppis epoch ratchet. */

/** A ciphertext on the wire: the libsignal message `type` (PREKEY vs WHISPER) plus the serialized
  * body. The type tells the receiver how to reconstruct the message; no key material is exposed. */
final case class RatchetMessage(msgType: Int, body: Array[Byte])

final class RatchetParty(val name: String, deviceId: Int = 1):
  val address: SignalProtocolAddress = new SignalProtocolAddress(name, deviceId)

  private val registrationId = KeyHelper.generateRegistrationId(false)
  private val identity = IdentityKeyPair.generate()
  private val store = new InMemorySignalProtocolStore(identity, registrationId)

  // One-time prekey + signed prekey + KYBER prekey, published for others to start a session with.
  // libsignal-client exposes the primitives directly (the old KeyHelper.generatePreKeys/
  // generateSignedPreKey convenience helpers were dropped), so we build the records ourselves: a
  // fresh keypair per prekey, and an identity-key signature over the prekey's serialized public key
  // (exactly what SessionBuilder.process verifies during the handshake).
  //
  // The `Curve` static helper was removed in 0.8x — key generation moved onto the types themselves
  // (`ECKeyPair.Companion.generate()`, Kotlin) and signing onto `ECPrivateKey.calculateSignature`.
  private val preKey: PreKeyRecord = new PreKeyRecord(1, ECKeyPair.Companion.generate())
  private val signedPreKey: SignedPreKeyRecord =
    val spkPair = ECKeyPair.Companion.generate()
    val signature = identity.getPrivateKey.calculateSignature(spkPair.getPublicKey.serialize())
    new SignedPreKeyRecord(1, System.currentTimeMillis(), spkPair, signature)
  // PQXDH: as of libsignal 0.8x the Kyber arm is MANDATORY — `PreKeyBundle` has a single
  // constructor and it requires the Kyber prekey + its signature, so a session can no longer be
  // established with the classic X3DH bundle alone. Signed by the same identity key as the signed
  // prekey. KYBER_1024 is the only KEMKeyType the library offers.
  private val kyberPreKey: KyberPreKeyRecord =
    val kyberPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
    val signature = identity.getPrivateKey.calculateSignature(kyberPair.getPublicKey.serialize())
    new KyberPreKeyRecord(1, System.currentTimeMillis(), kyberPair, signature)
  store.storePreKey(preKey.getId, preKey)
  store.storeSignedPreKey(signedPreKey.getId, signedPreKey)
  store.storeKyberPreKey(kyberPreKey.getId, kyberPreKey)
  // DEV/TEST HARNESS SHAPE — NOT a production key lifecycle. All three prekeys use a fixed id of 1,
  // are generated once per party, and are never rotated, replenished, or erased. libsignal treats a
  // bundle-published one-time prekey and Kyber prekey as SINGLE USE (`markKyberPreKeyUsed`); the
  // in-memory store no-ops that, which is why repeated sessions work here. A real store would reject
  // the second inbound PREKEY message against the same id. Production needs prekey rotation, a
  // replenished one-time pool, and erasure after use — the last of which also carries the project's
  // rule that key material must not outlive its epoch (Constitution II). Tracked in
  // specs/001-metadata-private-messenger/future-work.md ("Prekey lifecycle in the ratchet wrapper")
  // so this requirement is not carried solely by a source comment.

  /** The PQXDH prekey bundle a peer uses to open a session with this party. */
  def publishBundle(): PreKeyBundle =
    new PreKeyBundle(
      registrationId,
      deviceId,
      preKey.getId,
      preKey.getKeyPair.getPublicKey,
      signedPreKey.getId,
      signedPreKey.getKeyPair.getPublicKey,
      signedPreKey.getSignature,
      identity.getPublicKey,
      kyberPreKey.getId,
      kyberPreKey.getKeyPair.getPublicKey,
      kyberPreKey.getSignature
    )

  /** Establish an outbound session to `peer` from its published bundle (PQXDH). */
  def startSession(peer: SignalProtocolAddress, bundle: PreKeyBundle): Unit =
    new SessionBuilder(store, peer).process(bundle)

  /** Encrypt for `peer` (the double ratchet advances per message). */
  def encrypt(peer: SignalProtocolAddress, plaintext: Array[Byte]): RatchetMessage =
    val msg: CiphertextMessage = new SessionCipher(store, peer).encrypt(plaintext)
    RatchetMessage(msg.getType, msg.serialize)

  /** Decrypt a message from `peer`, reconstructing the right libsignal message type. A PREKEY
    * message also establishes this side's session (the first message in a conversation). */
  def decrypt(peer: SignalProtocolAddress, msg: RatchetMessage): Array[Byte] =
    val cipher = new SessionCipher(store, peer)
    msg.msgType match
      case CiphertextMessage.PREKEY_TYPE => cipher.decrypt(new PreKeySignalMessage(msg.body))
      case CiphertextMessage.WHISPER_TYPE => cipher.decrypt(new SignalMessage(msg.body))
      case other => throw new IllegalArgumentException(s"unknown ratchet message type $other")
