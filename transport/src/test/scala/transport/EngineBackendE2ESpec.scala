package transport

import metadatamessenger.store.v1.{store as spb}
import metadatamessenger.notify.v1.{notify as npb}
import crypto.Crypto
import engine.{BuddyRole, Engine, EngineEvent}
import ping.DevNotificationServer
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

      // --- Alice's side: a REAL engine driving the same backend (engine-driven ARQ send + notify) ---
      val aliceLabel = "alice-client".getBytes
      val sealer = DevNotificationServer(
        notifyKey
      ) // DEV: shares obsd's notify key (front seals in-enclave for real)
      val seal: (Long, Int, Array[Byte]) => Array[Byte] = (r, b, l) => sealer.issueToken(r, b, l)
      val aliceTransport = new GrpcRoundTransport(
        new EnclaveObliviousStore(storeStub, attested = false),
        new EnclaveNotificationClient(notifyStub, attested = false),
        notifySealer = Some(seal)
      )
      val alice = Engine(Some(aliceTransport), clientLabel = aliceLabel)
      val aPid =
        alice.addBuddy(secret, BuddyRole.Initiator, peerNotifyLabel = bobLabel).toOption.get.pairId
      alice.confirmBuddy(aPid, matched = true); alice.drainEvents()
      alice.sendMessage(aPid, "see you at the bridge")
      alice.tick(
        1L
      ) // engine writes the ARQ frame under Alice's round-1 token + signals Bob's notify

      // --- Bob ticks: notify-before-retrieval ---
      // Round-derived addressing reads the PREVIOUS round's writes, so Bob reads Alice's round-1 frame
      // when he ticks round 2 (readRound = 1).
      bob.tick(2L)
      val events = bob.drainEvents()
      val ni = events.indexWhere(_.isInstanceOf[EngineEvent.Notified])
      val mi = events.indexWhere(_.isInstanceOf[EngineEvent.MessageReceived])
      assert(ni >= 0, s"expected a notified event, got $events")
      assert(mi >= 0, s"expected a messageReceived event, got $events")
      assert(ni < mi, "notify must come before the retrieved message (FR-004)")
      val msg = events.collectFirst { case EngineEvent.MessageReceived(p, txt, _) => (p, txt) }
      assert(msg.contains((pair.pairId, "see you at the bridge")))

      // Single-use: a later tick (no new write in that round) delivers nothing.
      bob.tick(3L)
      assert(!bob.drainEvents().exists(_.isInstanceOf[EngineEvent.MessageReceived]))
    }
