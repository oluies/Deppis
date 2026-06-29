package transport

import metadatamessenger.store.v1.{store as spb}
import metadatamessenger.notify.v1.{notify as npb}
import crypto.Crypto
import engine.{BuddyRole, Engine, EngineEvent}
import frame.Frame
import handshake.Handshake
import ping.DevNotificationServer
import token.RetrievalToken
import org.scalatest.funsuite.AnyFunSuite

/** T032a end-to-end: the client engine, driven by [[GrpcRoundTransport]], performs notify-before-
  * retrieval against the REAL Rust `obsd` — proving the engine's `tick` emits `notified` and
  * `messageReceived` from an actual oblivious backend (not just the in-memory fake).
  *
  * The engine under test is "Bob" (Responder). The test plays "Alice" (Initiator): it stores a
  * framed message under Alice's outgoing token and signals Bob's notification, then ticks Bob's
  * engine and asserts the events surface. Opt-in via [[ObsdHarness]] (runs in the CI `integration`
  * job, which builds obsd). */
class EngineBackendE2ESpec extends AnyFunSuite with ObsdHarness:

  test("engine.tick over obsd: notify-before-retrieval emits notified then messageReceived"):
    val notifyKey = Array.tabulate(Crypto.KeyBytes)(i => (i * 9 + 4).toByte)
    withObsd(notifyKey) { channel =>
      val storeStub = spb.ObliviousStoreGrpc.blockingStub(channel)
      val notifyStub = npb.NotificationServiceGrpc.blockingStub(channel)

      // Bob's engine, wired to the real backend with his notify aggregation label.
      val bobLabel = "bob-client".getBytes
      val transport = new GrpcRoundTransport(
        new EnclaveObliviousStore(storeStub, attested = false),
        new EnclaveNotificationClient(notifyStub, attested = false)
      )
      val bob = Engine(Some(transport), clientLabel = bobLabel)

      val secret = "out-of-band-secret".getBytes
      val pair = bob.addBuddy(secret, BuddyRole.Responder).toOption.get
      bob.confirmBuddy(pair.pairId, matched = true)
      bob.drainEvents() // discard buddyConfirmed

      // --- Alice's side (played by the test) ---
      val pairKey = Handshake.init(secret).pairKey // same key Bob derived
      // Addressing layer: tokens + notify bit derive from the retained addressing root.
      val addrKey = engine.KeySchedule.addrKey(pairKey)
      val contentRoot = engine.KeySchedule.contentRoot(pairKey)
      // Alice (Initiator) stores her first message under her outgoing token, sealed by the SAME DH
      // double ratchet Bob's engine runs: bootstrap initiator vs. responder from the shared
      // contentRoot, so `alice.encrypt` produces exactly the 256-byte wire Bob's ratchet decrypts.
      val aliceToken = RetrievalToken.derive(addrKey, "Initiator", "Responder", 0L)
      val aliceRatchet = engine.DoubleRatchet.initInitiator(contentRoot)
      val inner =
        Frame.pad("see you at the bridge".getBytes, engine.DoubleRatchet.InnerSize).toOption.get
      val wire = aliceRatchet.encrypt(inner)
      val aliceStore = new EnclaveObliviousStore(storeStub, attested = false)
      assert(aliceStore.write(aliceToken, wire).isRight)
      // Alice signals Bob's notification under the PER-BUDDY bit Bob's engine checks for THIS round
      // (T041c rotates the bit per round; Bob ticks round 1L below) and the FIXED-WIDTH label tag Bob's
      // engine fetches under (uniform sealed-token length, no active-vs-idle size leak).
      val buddyBit = engine.NotifyDigest.bit(addrKey, 1L)
      val sealer = DevNotificationServer(notifyKey)
      val aliceNotify = new EnclaveNotificationClient(notifyStub, attested = false)
      assert(
        aliceNotify
          .signal(1L, sealer.issueToken(1L, buddyBit, engine.NotifyDigest.labelTag(bobLabel)))
          .isRight
      )

      // --- Bob ticks: notify-before-retrieval ---
      bob.tick(1L)
      val events = bob.drainEvents()
      val ni = events.indexWhere(_.isInstanceOf[EngineEvent.Notified])
      val mi = events.indexWhere(_.isInstanceOf[EngineEvent.MessageReceived])
      assert(ni >= 0, s"expected a notified event, got $events")
      assert(mi >= 0, s"expected a messageReceived event, got $events")
      assert(ni < mi, "notify must come before the retrieved message (FR-004)")
      val msg = events.collectFirst { case EngineEvent.MessageReceived(p, txt, _) => (p, txt) }
      assert(msg.contains((pair.pairId, "see you at the bridge")))

      // Single-use: a second tick (no new mail) delivers nothing.
      bob.tick(2L)
      assert(!bob.drainEvents().exists(_.isInstanceOf[EngineEvent.MessageReceived]))
    }
