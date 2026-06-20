package ratchet

import org.signal.libsignal.protocol.{IdentityKeyPair, SessionBuilder, SessionCipher, SignalProtocolAddress}
import org.signal.libsignal.protocol.ecc.Curve
import org.signal.libsignal.protocol.message.{CiphertextMessage, PreKeySignalMessage, SignalMessage}
import org.signal.libsignal.protocol.state.{PreKeyBundle, PreKeyRecord, SignedPreKeyRecord}
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import org.signal.libsignal.protocol.util.KeyHelper

/** Wrapper over the **audited** libsignal double-ratchet (T012, Constitution I — we wrap a vetted
  * implementation and NEVER reimplement the ratchet). Each [[RatchetParty]] is one local identity
  * with its own protocol store; it publishes a prekey bundle (X3DH), establishes a session from a
  * peer's bundle, and then exchanges messages. Forward secrecy and post-compromise security are
  * provided by the underlying library's double ratchet — this layer only adapts the API to Scala.
  *
  * DEPENDENCY (T012a): the backing crypto is `org.signal:libsignal-client` — Signal's MAINTAINED
  * libsignal (Rust core + Java/JNI bindings), which superseded the archived/EOL pure-JVM
  * `org.whispersystems:signal-protocol-java`. It ships a bundled native library loaded by the JVM at
  * runtime (no separate install; CI exercises the real ratchet on linux/mac). This thin wrapper is
  * the ONLY coupling point, so the migration was localized to this file. We wrap the vetted ratchet
  * and NEVER reimplement it (Constitution I). NOTE: this is the classic X3DH bundle (signed prekey +
  * one-time prekey); the post-quantum Kyber prekey arm of PQXDH is intentionally not used here. */

/** A ciphertext on the wire: the libsignal message `type` (PREKEY vs WHISPER) plus the serialized
  * body. The type tells the receiver how to reconstruct the message; no key material is exposed. */
final case class RatchetMessage(msgType: Int, body: Array[Byte])

final class RatchetParty(val name: String, deviceId: Int = 1):
  val address: SignalProtocolAddress = new SignalProtocolAddress(name, deviceId)

  private val registrationId = KeyHelper.generateRegistrationId(false)
  private val identity       = IdentityKeyPair.generate()
  private val store          = new InMemorySignalProtocolStore(identity, registrationId)

  // One-time prekey + signed prekey this party publishes for others to start a session with.
  // libsignal-client exposes the primitives directly (the old KeyHelper.generatePreKeys/
  // generateSignedPreKey convenience helpers were dropped), so we build the records ourselves:
  // a fresh Curve keypair per prekey, and an identity-key signature over the signed prekey's
  // serialized public key (exactly what SessionBuilder.process verifies during X3DH).
  private val preKey: PreKeyRecord = new PreKeyRecord(1, Curve.generateKeyPair())
  private val signedPreKey: SignedPreKeyRecord =
    val spkPair    = Curve.generateKeyPair()
    val signature  = Curve.calculateSignature(identity.getPrivateKey, spkPair.getPublicKey.serialize())
    new SignedPreKeyRecord(1, System.currentTimeMillis(), spkPair, signature)
  store.storePreKey(preKey.getId, preKey)
  store.storeSignedPreKey(signedPreKey.getId, signedPreKey)

  /** The X3DH prekey bundle a peer uses to open a session with this party. */
  def publishBundle(): PreKeyBundle =
    new PreKeyBundle(
      registrationId,
      deviceId,
      preKey.getId,
      preKey.getKeyPair.getPublicKey,
      signedPreKey.getId,
      signedPreKey.getKeyPair.getPublicKey,
      signedPreKey.getSignature,
      identity.getPublicKey
    )

  /** Establish an outbound session to `peer` from its published bundle (X3DH). */
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
      case CiphertextMessage.PREKEY_TYPE  => cipher.decrypt(new PreKeySignalMessage(msg.body))
      case CiphertextMessage.WHISPER_TYPE => cipher.decrypt(new SignalMessage(msg.body))
      case other => throw new IllegalArgumentException(s"unknown ratchet message type $other")
