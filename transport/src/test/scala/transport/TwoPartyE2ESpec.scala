package transport

import metadatamessenger.store.v1.{store as spb}
import metadatamessenger.notify.v1.{notify as npb}
import crypto.Crypto
import frame.Frame
import handshake.Handshake
import ping.DevNotificationServer
import privacy.Privacy
import token.RetrievalToken
import org.scalatest.funsuite.AnyFunSuite

/** End-to-end: two independent parties (Alice, Bob) pair out of band, then a real message is
  * delivered **metadata-privately** through the real Rust `obsd` sidecar — exercising the whole
  * path the way the system actually runs:
  *
  *   pairing (Handshake) → retrieval-token PRF → 256-byte framing → oblivious store (Rust, PONG) →
  *   oblivious notify (Rust, PING) → retrieval → unframe.
  *
  * Opt-in via [[ObsdHarness]] (cancels if `obsd` is absent); runs in the CI `integration` job, which
  * builds `obsd`. This is the top-level proof that the layers compose into a working, oblivious,
  * single-use message delivery across the process boundary. */
class TwoPartyE2ESpec extends AnyFunSuite with ObsdHarness:

  // Symmetric, derivation-only ids shared by the convention "lower party is the sender label".
  private val Alice = "alice"
  private val Bob   = "bob"

  test("pairing: both parties derive the same safety number; a tampered secret does not"):
    val secret = "shared-out-of-band-secret".getBytes
    val a = Handshake.init(secret)
    val b = Handshake.init(secret)
    assert(a.pairId == b.pairId)
    assert(a.safetyNumber == b.safetyNumber)        // out-of-band comparison succeeds
    assert(a.pairKey.sameElements(b.pairKey))        // same per-pair key derived independently
    val tampered = Handshake.init("shared-out-of-band-secreT".getBytes)
    assert(tampered.safetyNumber != a.safetyNumber)  // tamper ⇒ mismatch ⇒ rejected

  test("Alice → Bob message is delivered through obsd (oblivious, single-use), wrong token misses"):
    val notifyKey = Array.tabulate(Crypto.KeyBytes)(i => (i * 3 + 1).toByte)
    withObsd(notifyKey) { channel =>
      val pair = Handshake.init("e2e-secret".getBytes)
      // Each party derives the SAME retrieval token from the shared pair key (non-recurrent counter).
      val tokenA = RetrievalToken.derive(pair.pairKey, Alice, Bob, counter = 0L)
      val tokenB = RetrievalToken.derive(pair.pairKey, Alice, Bob, counter = 0L)
      assert(RetrievalToken.equalsCT(tokenA, tokenB))

      val aliceStore = new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested = false)
      val bobStore   = new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested = false)

      // Alice frames + stores under the retrieval token (the store never learns sender/receiver).
      val plaintext = "meet at the usual place"
      val frame     = Frame.pad(plaintext.getBytes).toOption.get
      assert(aliceStore.write(tokenA, frame).isRight)

      // Obliviousness / token isolation — checked WHILE the message is still present: a token for a
      // different counter must NOT retrieve the message stored under tokenA (no false delivery, and
      // the wrong read must not consume it either).
      val wrong = RetrievalToken.derive(pair.pairKey, Alice, Bob, counter = 99L)
      assert(bobStore.read(wrong).toOption.flatten.isEmpty)

      // Bob retrieves with the independently-derived token and recovers the plaintext — proving the
      // message survived the wrong-token read above.
      val got = bobStore.read(tokenB).toOption.flatten
      assert(got.exists(_.sameElements(frame)))
      assert(Frame.unpad(got.get).toOption.map(new String(_)).contains(plaintext))

      // Single-use: a replayed retrieval returns nothing (FR — no residual retention).
      assert(bobStore.read(tokenB).toOption.flatten.isEmpty)
    }

  test("notify: Bob learns 'mail waiting' for the round without the store revealing who wrote"):
    val notifyKey = Array.tabulate(Crypto.KeyBytes)(i => (i * 5 + 2).toByte)
    withObsd(notifyKey) { channel =>
      val receiver = DevNotificationServer(notifyKey) // seals tokens with the key obsd opens with
      val notify   = new EnclaveNotificationClient(npb.NotificationServiceGrpc.blockingStub(channel), attested = false)
      val bobLabel = "bob-agg-label".getBytes
      val bobBit   = 7

      // No mail yet → all-zero digest (carrier-indistinguishable: reveals nothing).
      assert(notify.fetchDigest(10L, bobLabel).toOption.get.forall(_ == 0))

      // Alice signals Bob's slot for round 10; Bob sees exactly that bit, nothing about identity.
      assert(notify.signal(10L, receiver.issueToken(10L, bobBit, bobLabel)).isRight)
      val digest = notify.fetchDigest(10L, bobLabel).toOption.get
      assert((digest(bobBit >> 3) & (1 << (bobBit & 7))) != 0)
    }

  test("an unattested enclave-target front is labeled DEV (no metadata privacy claim)"):
    withObsd(Array.fill(Crypto.KeyBytes)(0.toByte)) { channel =>
      val store = new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested = false)
      assert(!store.metadataPrivate)
      assert(store.label == Privacy.DevLabel)
    }
