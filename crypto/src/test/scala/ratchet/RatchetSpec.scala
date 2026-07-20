package ratchet

import org.scalatest.funsuite.AnyFunSuite
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.PreKeyBundle

/** T012: exercises the wrapped audited libsignal double ratchet end to end between two parties.
  * We assert the observable ratchet properties (round-trip both ways, the ratchet advances so the
  * same plaintext yields different ciphertexts, out-of-order delivery still decrypts) rather than
  * re-deriving any crypto — the implementation is the vetted library's, not ours (Constitution I).
  *
  * Scope: this covers the JVM **cross-check reference**, not the production content ratchet
  * (`engine.DoubleRatchet`, covered by `DoubleRatchetModelSpec` and the cross-platform specs). */
class RatchetSpec extends AnyFunSuite:

  /** A serialized ML-KEM-1024 public key: 1568 key bytes + 1 leading libsignal key-type byte. Named
    * rather than inlined so the assertion below says what it is pinning, and so a future libsignal
    * parameter-set or prefix change points here instead of at a bare number. */
  private val Kyber1024SerializedPubLen = 1568 + 1

  /** `Throwable.toString` is class + `getMessage`, so a cause-only exception (which
    * `InvalidKeyException` supports) renders as a bare class name — losing the very diagnostic the
    * failure messages below exist to carry. Fall back to the cause when there is no message. */
  private def describe(t: Throwable): String =
    val detail = Option(t.getMessage)
      .orElse(Option(t.getCause).map(c => s"caused by $c"))
      .getOrElse("<no message or cause>")
    s"${t.getClass.getName}: $detail"

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
    assert(
      kyberPub.serialize().length == Kyber1024SerializedPubLen,
      s"unexpected Kyber public key length: ${kyberPub.serialize().length} " +
        s"(expected $Kyber1024SerializedPubLen for ${KEMKeyType.KYBER_1024})"
    )
    val sig = bundle.getKyberPreKeySignature
    assert(sig != null && sig.nonEmpty, "Kyber prekey is unsigned")
    // The signature must verify under the SAME identity key that signs the classic signed prekey —
    // that binding is what stops a Kyber arm being swapped in by anyone but the bundle's owner.
    assert(
      bundle.getIdentityKey.getPublicKey.verifySignature(kyberPub.serialize(), sig),
      "Kyber prekey signature does not verify under the bundle's identity key"
    )

  /** Rebuild `b`'s fields into a fresh bundle, substituting `kyberSig`. Both halves of the test
    * below construct their bundle through this, so the bundles differ only in the signature bytes.
    * (The two halves do use different INITIATING parties — a store that had already processed this
    * bundle would not re-exercise the same path — so they differ in initiator identity too. The
    * shared reconstruction is what makes the comparison meaningful, not total isolation.) */
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

  // The negative half of the above. Checking that a well-formed bundle verifies says nothing about
  // whether anyone ENFORCES it: the positive test would pass just as happily against a library that
  // skipped Kyber signature verification altogether. This asserts the actual threat named there —
  // a Kyber arm swapped in by someone other than the bundle's owner must be REJECTED at handshake.
  test("a bundle whose Kyber signature does not verify is rejected at startSession"):
    val bob = new RatchetParty("bob")
    val good = bob.publishBundle()
    val sig = good.getKyberPreKeySignature

    // Control: the same reconstruction with the signature UNMODIFIED must be accepted. Without it,
    // anything that broke the rebuild itself (constructor field-order drift, a getter re-encoding a
    // key) would leave the negative case below green while it no longer tested enforcement at all.
    // Report the cause in the MESSAGE — sbt's reporter prints only that, not fail()'s cause arg.
    try new RatchetParty("carol-ctl").startSession(bob.address, rebuilt(good, sig))
    catch
      case e: Throwable =>
        fail(
          s"positive control: unmodified Kyber signature must be accepted, got ${describe(e)}",
          e
        )

    // One flipped bit in that same signature must be rejected. Attribution rests on the control
    // above: libsignal raises InvalidKeyException for a bad SIGNED-prekey signature and malformed
    // key material too, so the type alone does not localise the failure to the Kyber arm — what
    // does is that the control differs only in these bytes. Weaken the control and this stops
    // proving Kyber enforcement.
    val ex = intercept[org.signal.libsignal.protocol.InvalidKeyException](
      new RatchetParty("alice-neg")
        .startSession(bob.address, rebuilt(good, sig.updated(0, (sig(0) ^ 0x01).toByte)))
    )
    // Substring tracks a libsignal message with no compatibility guarantee — update it on a bump,
    // do not drop the check. Option(): InvalidKeyException has cause-only constructors, so
    // getMessage can be null.
    assert(
      Option(ex.getMessage).exists(_.contains("invalid signature")),
      s"rejected for the wrong reason: ${describe(ex)}"
    )
