package transport

import com.google.protobuf.ByteString
import crypto.Crypto
import engine.{BuddyRole, Engine, EngineEvent, RoundTransport}
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import metadatamessenger.notify.v1.notify as npb
import metadatamessenger.provider.v1.provider as ppb
import metadatamessenger.store.v1.store as spb
import org.scalatest.funsuite.AnyFunSuite
import ping.DevNotificationServer

import scala.collection.mutable
import scala.concurrent.ExecutionContext.Implicits.global

/** The networked provider (contract `provider.proto`, T038, `design/offline-delegation.md` §3):
  * devices reach their provider ONLY over gRPC, through [[GrpcProviderClient]], and never touch the
  * backend themselves.
  *
  *   - the contract's session rules;
  *   - T037 end to end over gRPC, with the dev backend (always runs);
  *   - the same over the REAL Rust `obsd` as the provider's backend — device → gRPC → provider →
  *     gRPC → obsd store + notify (opt-in via [[ObsdHarness]]; runs in CI's integration job). */
class ProviderServiceSpec extends AnyFunSuite with ObsdHarness:

  private val Horizon = 120
  private val Refresh = 20
  private val aLabel = "alice-label".getBytes("UTF-8")
  private val bLabel = "bob-label".getBytes("UTF-8")
  private val oob = "provider-service-oob".getBytes("UTF-8")

  /** An in-process gRPC provider front over `backend`; `body` gets the provider and a raw stub. */
  private def withProviderService(backend: RoundTransport)(
      body: (_root_.provider.Provider, ppb.ProviderServiceGrpc.ProviderServiceBlockingStub) => Unit
  ): Unit =
    val p = _root_.provider.Provider(backend, maxHorizon = Horizon)
    val name = InProcessServerBuilder.generateName()
    val server = InProcessServerBuilder
      .forName(name)
      .directExecutor()
      .addService(ppb.ProviderServiceGrpc.bindService(ProviderServiceImpl(p), global))
      .build()
      .start()
    val channel = InProcessChannelBuilder.forName(name).directExecutor().build()
    try body(p, ppb.ProviderServiceGrpc.blockingStub(channel))
    finally
      channel.shutdownNow()
      server.shutdownNow(): Unit

  private def devBackend(): RoundTransport =
    _root_.provider.DevProviderBackend(notifications =
      DevNotificationServer(Array.tabulate(Crypto.KeyBytes)(_.toByte))
    )

  // ================================================================ the contract's session rules

  test("sessions: a user registers once; every other call needs that user's session"):
    withProviderService(devBackend()) { (p, stub) =>
      val reg = stub.register(ppb.RegisterRequest("alice", ByteString.copyFrom(aLabel)))
      assert(reg.ok && reg.session.size == 32, s"a 32-byte session: $reg")
      val again = stub.register(ppb.RegisterRequest("alice", ByteString.copyFrom(aLabel)))
      assert(!again.ok && again.session.isEmpty, "a user name is registered once")

      val wrong = ByteString.copyFrom(new Array[Byte](32))
      p.openRound(1).toOption.get
      assert(!stub.getDigest(ppb.GetDigestRequest("alice", wrong, 1)).ok)
      assert(stub.getDigest(ppb.GetDigestRequest("alice", reg.session, 1)).ok)
      val ops =
        ProviderProto.toProto(Engine(clientLabel = aLabel).beginRound(1, Array.emptyByteArray))
      assert(!stub.submitLive(ppb.SubmitLiveRequest("alice", wrong, Some(ops))).accepted)
      assert(!stub.submitLive(ppb.SubmitLiveRequest("mallory", reg.session, Some(ops))).accepted)
      assert(stub.submitLive(ppb.SubmitLiveRequest("alice", reg.session, Some(ops))).accepted)
      assert(!stub.uploadBundle(ppb.UploadBundleRequest("alice", wrong, 2, Nil)).ok)
      p.closeRound(1).toOption.get: Unit
      assert(!stub.collectReceipt(ppb.CollectReceiptRequest("alice", wrong, 1)).found)
      assert(stub.collectAll(ppb.CollectAllRequest("alice", wrong)).receipts.isEmpty)
      val got = stub.collectReceipt(ppb.CollectReceiptRequest("alice", reg.session, 1))
      assert(got.found && got.receipt.exists(_.ranLive), "alice's own live set ran")
    }

  // ======================================================= T037 end to end, devices over gRPC only

  /** Alice and Bob, each with ONLY a gRPC route to the provider. Bob goes offline, Alice queues two
    * messages and then disconnects abruptly too; Bob returns and gets m1 from Alice's bundle while
    * she is away; Alice returns and m2 follows, in order. */
  private def offlineScenario(p: _root_.provider.Provider, client: GrpcProviderClient): Unit =
    val alice = Engine(clientLabel = aLabel) // no transport: the provider is the only route
    val bob = Engine(clientLabel = bLabel)
    val pid = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = bLabel).toOption.get.pairId
    bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = aLabel).toOption.get: Unit
    alice.confirmBuddy(pid, matched = true).toOption.get
    bob.confirmBuddy(pid, matched = true).toOption.get
    alice.drainEvents(); bob.drainEvents()
    val sa = _root_.provider.ProviderSession("alice", alice, client, aLabel, Refresh, Horizon)
    val sb = _root_.provider.ProviderSession("bob", bob, client, bLabel, Refresh, Horizon)
    var aliceUp = true
    var bobUp = true
    val toBob = mutable.ArrayBuffer.empty[(Long, String)]
    def round(r: Long): Unit =
      p.openRound(r).toOption.get
      if aliceUp then sa.beforeCutoff(r)
      if bobUp then sb.beforeCutoff(r)
      p.closeRound(r).toOption.get: Unit
      if aliceUp then sa.afterCutoff(r)
      if bobUp then sb.afterCutoff(r)
      toBob ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => (r, t) }
      alice.drainEvents(): Unit

    for r <- 1L to 10L do round(r)
    bobUp = false
    alice.sendMessage(pid, "m1"): Unit
    alice.sendMessage(pid, "m2"): Unit
    for r <- 11L to 30L do round(r)
    aliceUp = false
    for r <- 31L to 59L do round(r)
    assert(toBob.isEmpty)
    bobUp = true
    sb.collectAway(): Unit
    for r <- 60L to 89L do round(r)
    assert(
      toBob.map(_._2) == Seq("m1"),
      s"m1 reaches bob from alice's bundle while she is away: $toBob"
    )
    aliceUp = true
    sa.collectAway(): Unit
    for r <- 90L to 119L do round(r)
    assert(toBob.map(_._2) == Seq("m1", "m2"), s"m2 follows in order, each once: $toBob")

  test("T037 over gRPC: devices reach the backend only through the provider (dev backend)"):
    withProviderService(devBackend()) { (p, stub) =>
      offlineScenario(p, GrpcProviderClient(stub))
    }

  test("T037 over gRPC with the real Rust obsd as the provider's backend"):
    val notifyKey = Array.tabulate(Crypto.KeyBytes)(i => (i * 5 + 3).toByte)
    // Cover writes are never read, so they accumulate: give the store room for the whole run
    // (two users × ~120 rounds) so no write is rejected for a reason unrelated to the provider.
    withObsd(notifyKey, capacity = 4096) { channel =>
      // The PROVIDER's backend connection: store + notify on obsd. DEV: the provider holds the dev
      // notify key to seal signals (Phase 4 moves sealing to the device, §4.2).
      val sealer = DevNotificationServer(notifyKey)
      val backend = GrpcRoundTransport(
        EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested = false),
        EnclaveNotificationClient(
          npb.NotificationServiceGrpc.blockingStub(channel),
          attested = false
        ),
        notifySealer = Some((r, b, l) => sealer.issueToken(r, b, l))
      )
      withProviderService(backend) { (p, stub) =>
        offlineScenario(p, GrpcProviderClient(stub))
      }
    }
