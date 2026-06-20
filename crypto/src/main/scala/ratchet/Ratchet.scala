package ratchet

import org.whispersystems.libsignal.{SessionBuilder, SessionCipher, SignalProtocolAddress}
import org.whispersystems.libsignal.protocol.{CiphertextMessage, PreKeySignalMessage, SignalMessage}
import org.whispersystems.libsignal.state.{PreKeyBundle, PreKeyRecord, SignedPreKeyRecord}
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore
import org.whispersystems.libsignal.util.KeyHelper

/** Wrapper over the **audited** libsignal double-ratchet (T012, Constitution I — we wrap a vetted
  * implementation and NEVER reimplement the ratchet). Each [[RatchetParty]] is one local identity
  * with its own protocol store; it publishes a prekey bundle (X3DH), establishes a session from a
  * peer's bundle, and then exchanges messages. Forward secrecy and post-compromise security are
  * provided by the underlying library's double ratchet — this layer only adapts the API to Scala.
  *
  * DEPENDENCY STATUS (tracked): the backing `org.whispersystems:signal-protocol-java` is the
  * historically-audited pure-JVM libsignal, but its upstream repo is **archived/EOL** — Signal
  * moved its protocol core to `libsignal` (Rust core + Java bindings, `org.signal:libsignal-client`),
  * so this pin receives no further security patches. We keep it because it is pure-JVM (no native
  * libs in CI) and audited, and because this thin wrapper is the ONLY coupling point — migrating to
  * `org.signal:libsignal-client` later is localized to this file. See tasks.md T012 for the tracked
  * migration follow-up; do not mistake this pin for a currently-maintained dependency. */

/** A ciphertext on the wire: the libsignal message `type` (PREKEY vs WHISPER) plus the serialized
  * body. The type tells the receiver how to reconstruct the message; no key material is exposed. */
final case class RatchetMessage(msgType: Int, body: Array[Byte])

final class RatchetParty(val name: String, deviceId: Int = 1):
  val address: SignalProtocolAddress = new SignalProtocolAddress(name, deviceId)

  private val registrationId = KeyHelper.generateRegistrationId(false)
  private val identity       = KeyHelper.generateIdentityKeyPair()
  private val store          = new InMemorySignalProtocolStore(identity, registrationId)

  // One-time prekey + signed prekey this party publishes for others to start a session with.
  private val preKey: PreKeyRecord             = KeyHelper.generatePreKeys(0, 1).get(0)
  private val signedPreKey: SignedPreKeyRecord = KeyHelper.generateSignedPreKey(identity, 0)
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
