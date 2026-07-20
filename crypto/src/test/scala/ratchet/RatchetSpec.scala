package ratchet

import org.scalatest.funsuite.AnyFunSuite
import org.signal.libsignal.protocol.state.PreKeyBundle

/** T012: exercises the wrapped audited libsignal double ratchet end to end between two parties.
  * We assert the observable ratchet properties (round-trip both ways, the ratchet advances so the
  * same plaintext yields different ciphertexts, out-of-order delivery still decrypts) rather than
  * re-deriving any crypto — the implementation is the vetted library's, not ours (Constitution I). */
class RatchetSpec extends AnyFunSuite:

  private def utf8(s: String): Array[Byte] = s.getBytes("UTF-8")
  private def str(b: Array[Byte]): String = new String(b, "UTF-8")

  /** Alice opens a session from Bob's published bundle and sends the first (PREKEY) message. */
  private def paired(): (RatchetParty, RatchetParty) =
    val alice = new RatchetParty("alice")
    val bob = new RatchetParty("bob")
    alice.startSession(bob.address, bob.publishBundle())
    (alice, bob)

  test("Alice → Bob first message establishes the session and decrypts"):
    val (alice, bob) = paired()
    val ct = alice.encrypt(bob.address, utf8("hello bob"))
    assert(str(bob.decrypt(alice.address, ct)) == "hello bob")

  test("conversation flows both ways after the session is established"):
    val (alice, bob) = paired()
    bob.decrypt(alice.address, alice.encrypt(bob.address, utf8("hi"))) // establish on Bob's side
    val reply = bob.encrypt(alice.address, utf8("hi back"))
    assert(str(alice.decrypt(bob.address, reply)) == "hi back")
    val again = alice.encrypt(bob.address, utf8("how are you"))
    assert(str(bob.decrypt(alice.address, again)) == "how are you")

  test("the ratchet advances: the same plaintext yields different ciphertexts"):
    val (alice, bob) = paired()
    val c1 = alice.encrypt(bob.address, utf8("same"))
    val c2 = alice.encrypt(bob.address, utf8("same"))
    assert(!c1.body.sameElements(c2.body), "ratchet must not produce identical ciphertexts")
    // Both still decrypt to the original plaintext.
    assert(str(bob.decrypt(alice.address, c1)) == "same")
    assert(str(bob.decrypt(alice.address, c2)) == "same")

  test("out-of-order delivery still decrypts (per-message keys)"):
    val (alice, bob) = paired()
    bob.decrypt(alice.address, alice.encrypt(bob.address, utf8("m0"))) // establish
    val m1 = alice.encrypt(bob.address, utf8("m1"))
    val m2 = alice.encrypt(bob.address, utf8("m2"))
    // Deliver m2 before m1 — the double ratchet keeps skipped message keys.
    assert(str(bob.decrypt(alice.address, m2)) == "m2")
    assert(str(bob.decrypt(alice.address, m1)) == "m1")

  test("messages are PREKEY type until the peer replies, then WHISPER type"):
    import org.signal.libsignal.protocol.message.CiphertextMessage
    val (alice, bob) = paired()
    // Alice keeps sending PREKEY messages until she hears back from Bob (she can't yet know he has
    // processed her session). Both her first and second pre-reply messages are PREKEY type.
    val first = alice.encrypt(bob.address, utf8("a"))
    assert(first.msgType == CiphertextMessage.PREKEY_TYPE)
    bob.decrypt(alice.address, first)
    assert(alice.encrypt(bob.address, utf8("b")).msgType == CiphertextMessage.PREKEY_TYPE)
    // Once Bob replies and Alice processes it, the session is fully established → WHISPER type.
    alice.decrypt(bob.address, bob.encrypt(alice.address, utf8("r")))
    assert(alice.encrypt(bob.address, utf8("c")).msgType == CiphertextMessage.WHISPER_TYPE)

  test("a tampered ciphertext is rejected — the wrapper surfaces the library's auth failure"):
    val (alice, bob) = paired()
    val ct = alice.encrypt(bob.address, utf8("secret"))
    // Flip a byte in the body; the library MUST reject it (MAC/parse failure), never return garbage.
    val corrupted =
      ct.copy(body = ct.body.updated(ct.body.length - 1, (ct.body.last ^ 0x01).toByte))
    assertThrows[Exception](bob.decrypt(alice.address, corrupted))

  test("an unknown message type is rejected, not silently mishandled"):
    val (alice, bob) = paired()
    val ct = alice.encrypt(bob.address, utf8("x"))
    assertThrows[IllegalArgumentException](bob.decrypt(alice.address, ct.copy(msgType = 99)))

  // PQXDH: libsignal 0.8x made the Kyber arm mandatory, so the published bundle MUST carry a Kyber
  // prekey and its signature. Pinned explicitly rather than left implicit in "the session works" —
  // if a future version made the arm optional again, the round-trip tests above would keep passing
  // while the handshake silently lost its post-quantum leg, which is exactly the regression this
  // project cannot afford to miss.
  test("the published bundle carries a signed Kyber prekey (PQXDH, not classic X3DH)"):
    val bundle = new RatchetParty("carol").publishBundle()
    val kyberPub = bundle.getKyberPreKey
    assert(kyberPub != null, "bundle has no Kyber prekey — the handshake would be classic X3DH")
    // Kyber-1024 public keys are 1568 bytes, +1 for libsignal's key-type prefix byte.
    assert(
      kyberPub.serialize().length == 1569,
      s"unexpected Kyber public key length: ${kyberPub.serialize().length}"
    )
    val sig = bundle.getKyberPreKeySignature
    assert(sig != null && sig.nonEmpty, "Kyber prekey is unsigned")
    // The signature must verify under the SAME identity key that signs the classic signed prekey —
    // that binding is what stops a Kyber arm being swapped in by anyone but the bundle's owner.
    assert(
      bundle.getIdentityKey.getPublicKey.verifySignature(kyberPub.serialize(), sig),
      "Kyber prekey signature does not verify under the bundle's identity key"
    )

  // The negative half of the above. Checking that a well-formed bundle verifies says nothing about
  // whether anyone ENFORCES it: the positive test would pass just as happily against a library that
  // skipped Kyber signature verification altogether. This asserts the actual threat named there —
  // a Kyber arm swapped in by someone other than the bundle's owner must be REJECTED at handshake.
  /** Rebuild `b`'s fields into a fresh bundle, substituting `kyberSig`. Both halves of the test
    * below go through this, so the ONLY difference between them is the signature bytes. */
  private def rebuilt(b: PreKeyBundle, kyberSig: Array[Byte]): PreKeyBundle =
    new PreKeyBundle(
      b.getRegistrationId,
      b.getDeviceId,
      b.getPreKeyId,
      b.getPreKey,
      b.getSignedPreKeyId,
      b.getSignedPreKey,
      b.getSignedPreKeySignature,
      b.getIdentityKey,
      b.getKyberPreKeyId,
      b.getKyberPreKey,
      kyberSig
    )

  test("a bundle whose Kyber signature does not verify is rejected at startSession"):
    val bob = new RatchetParty("bob")
    val good = bob.publishBundle()
    val sig = good.getKyberPreKeySignature

    // The POSITIVE CONTROL lives in the test, not in a commit message: the same reconstruction with
    // the unmodified signature must SUCCEED. Without it, anything that made a rebuilt bundle fail
    // for an unrelated reason (constructor field-order drift, a getter re-encoding a key) would
    // leave the negative case green while it had stopped testing signature enforcement entirely.
    new RatchetParty("carol-ctl").startSession(bob.address, rebuilt(good, sig))

    // ...and one flipped bit in that same signature must be rejected. The type is pinned rather
    // than `Exception`: a rejection for ANY other reason (native load failure, a future arity
    // change, an untrusted-identity error) does not show the Kyber signature was verified.
    // Verified empirically — libsignal raises InvalidKeyException("invalid signature detected").
    assertThrows[org.signal.libsignal.protocol.InvalidKeyException](
      new RatchetParty("alice-neg")
        .startSession(bob.address, rebuilt(good, sig.updated(0, (sig(0) ^ 0x01).toByte)))
    )
