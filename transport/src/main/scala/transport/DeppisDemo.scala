package transport

import io.grpc.{ManagedChannel, ManagedChannelBuilder}
import java.io.File
import java.net.{InetSocketAddress, ServerSocket, Socket}
import java.util.concurrent.TimeUnit
import metadatamessenger.store.v1.{store as spb}
import metadatamessenger.notify.v1.{notify as npb}
import engine.{BuddyRole, Engine, EngineEvent}
import metadatamessenger.provider.v1.provider as ppb
import scala.concurrent.ExecutionContext
import ping.DevNotificationServer
import crypto.Crypto

/** Headless runnable demo (the "core" prototype). Two independent client engines — Alice and Bob —
  * pair out of band, then Alice sends Bob a message delivered through the **real Rust `obsd`
  * sidecar**, with both devices routed through an untrusted SERVICE PROVIDER
  * (`design/offline-delegation.md`): devices talk only to the provider over TLS 1.3, and the
  * provider runs one write and one read per user per round against obsd — the device's live set
  * when it is online, its standing bundle when it is not — so an observer of the backend cannot
  * tell an active round from an idle one, or an online device from an offline one (FR-012).
  *
  * THIS IS A DEV BUILD: the dev store/notify provide NO access-pattern privacy and the run is NOT
  * attested, and the provider relays plaintext until Phase 4, so it reports the
  * `DEV, NO METADATA PRIVACY` label (Constitution IV). The provider also seals notify tokens with
  * the dev key obsd opens them with; that is clearly marked below.
  *
  * Run: build obsd first (`cargo build --bin obsd` in `oblivious-sidecar/`), then
  *   `sbt "transport/runMain transport.DeppisDemo"`
  * Point `OBSD_BIN` at the binary if it is not on a default relative path. */
object DeppisDemo:

  private def log(who: String, msg: String): Unit = println(f"  [$who%-5s] $msg")

  // Small horizon and refresh cadence so the demo is short; production uses engine.Delegation.
  private val Horizon = 60
  private val Refresh = 10

  /** The dev notify key obsd opens tokens with AND the PING-front stand-in seals with — one source
    * so the two never silently diverge. A fresh array per call (never shared mutable state). */
  private[transport] def devNotifyKey: Array[Byte] =
    Array.tabulate(Crypto.KeyBytes)(i => (i * 7 + 3).toByte)

  def main(args: Array[String]): Unit =
    val notifyKey = devNotifyKey
    val bin = findObsd().getOrElse {
      System.err.println(
        "obsd binary not found. Build it with `cargo build --bin obsd` in oblivious-sidecar/, " +
          "or set OBSD_BIN to its path."
      )
      sys.exit(2)
    }
    val port = freePort()
    println(s"  spawning obsd (real Rust sidecar) on 127.0.0.1:$port …")
    val proc = startObsd(bin, port, notifyKey)
    // Compute the exit code INSIDE try/finally, then exit AFTER teardown — sys.exit halts the JVM
    // without running finally, which would orphan the spawned obsd (it holds its port).
    val code =
      try
        if !awaitReady(port, 10000) then
          System.err.println(s"obsd did not become ready on port $port")
          3
        else
          val channel = ManagedChannelBuilder.forAddress("127.0.0.1", port).usePlaintext().build()
          val delivered =
            try run(channel, notifyKey)
            finally channel.shutdownNow()
          if delivered then 0 else 1
      finally
        proc.destroy()
        if !proc.waitFor(5, TimeUnit.SECONDS) then proc.destroyForcibly()
    sys.exit(code)

  /** Drive the whole flow against an already-connected `obsd` channel. Returns `true` iff Alice's
    * message reached Bob. Pure of process management / `sys.exit`, so the integration suite can run
    * it against the test `ObsdHarness`.
    *
    * PROVIDER-ROUTED (`design/offline-delegation.md` §3): the two devices never touch obsd. Each
    * reaches its service provider over TLS 1.3 (`ProviderService`), and the provider alone talks to
    * obsd. The demo plays the provider's round clock, so the run is fast and deterministic. The
    * story is the case delegation exists for: Bob goes offline, Alice queues a message and then
    * disconnects too, Bob comes back — and the message reaches him from Alice's standing bundle
    * while she is still away. */
  def run(channel: ManagedChannel, notifyKey: Array[Byte]): Boolean =
    val storeStub = spb.ObliviousStoreGrpc.blockingStub(channel)
    val notifyStub = npb.NotificationServiceGrpc.blockingStub(channel)
    val aliceLabel = "alice-client".getBytes
    val bobLabel = "bob-client".getBytes
    // The PROVIDER's backend connection to obsd. DEV: the provider seals notify tokens with the key
    // obsd opens with; Phase 4 moves sealing onto the device (design §4.2).
    val sealer = DevNotificationServer(notifyKey)
    val backend = new GrpcRoundTransport(
      new EnclaveObliviousStore(storeStub, attested = false),
      new EnclaveNotificationClient(notifyStub, attested = false),
      notifySealer = Some((r, b, l) => sealer.issueToken(r, b, l))
    )
    val provider = _root_.provider.Provider(backend, maxHorizon = Horizon)
    given ExecutionContext = ExecutionContext.global
    val server = round.TlsRoundServer.bindProvider(provider)
    val channels = Seq(server.trustingChannel(), server.trustingChannel())
    try
      def route(ch: ManagedChannel) = GrpcProviderClient(ppb.ProviderServiceGrpc.blockingStub(ch))
      // No transport of their own: the provider is each device's only backend connection.
      val alice = Engine(clientLabel = aliceLabel)
      val bob = Engine(clientLabel = bobLabel)

      println("\n== Deppis metadata-private messenger — headless demo (provider-routed) ==")
      println(
        s"""  provider: label="${provider.label}" metadataPrivate=${provider.metadataPrivate}"""
      )
      println(s"  devices ↔ provider: TLS 1.3 on port ${server.port};  provider ↔ obsd: gRPC\n")

      // 1) Out-of-band pairing: same shared secret, opposite roles; safety numbers compared by hand.
      val secret = "meet-me-at-the-old-bridge".getBytes
      val a = alice.addBuddy(secret, BuddyRole.Initiator, peerNotifyLabel = bobLabel).toOption.get
      alice.confirmBuddy(a.pairId, matched = true); alice.drainEvents()
      val b = bob.addBuddy(secret, BuddyRole.Responder, peerNotifyLabel = aliceLabel).toOption.get
      bob.confirmBuddy(b.pairId, matched = true); bob.drainEvents()
      log("alice", s"paired with bob — safetyNumber ${a.safetyNumber}")
      log("bob", s"paired with alice — safetyNumber ${b.safetyNumber}")
      if a.safetyNumber != b.safetyNumber then
        println("  ✗ safety numbers differ — pairing would be rejected")
        return false
      println("  ✓ safety numbers match → out-of-band verification succeeds\n")

      val sa = _root_.provider.ProviderSession(
        "alice",
        alice,
        route(channels(0)),
        aliceLabel,
        Refresh,
        Horizon
      )
      val sb =
        _root_.provider.ProviderSession("bob", bob, route(channels(1)), bobLabel, Refresh, Horizon)
      var aliceUp = true
      var bobUp = true
      var delivered: Option[(Long, String)] = None
      // One round: the provider opens it, online devices hand in their live sets, the cutoff runs
      // exactly one operation set per user (live, else the standing-bundle slot), then online
      // devices apply their receipts.
      def round(r: Long): Unit =
        provider.openRound(r).toOption.get
        if aliceUp then sa.beforeCutoff(r): Unit
        if bobUp then sb.beforeCutoff(r): Unit
        val ran = provider.closeRound(r).toOption.get // users whose operations ran this round
        if aliceUp then sa.afterCutoff(r)
        if bobUp then sb.afterCutoff(r)
        alice.drainEvents(): Unit
        bob.drainEvents().collectFirst { case EngineEvent.MessageReceived(_, t, _) => t }.foreach {
          t => delivered = delivered.orElse(Some(r -> t))
        }
        def who(up: Boolean) = if up then "live  " else "bundle"
        log("round", f"$r%3d: alice=${who(aliceUp)} bob=${who(bobUp)}  → backend saw $ran writes")

      val message = "see you at dusk"
      for r <- 1L to 3L do round(r)
      bobUp = false
      log("bob", "goes offline — no warning; his standing bundle keeps his rounds going")
      alice.sendMessage(a.pairId, message)
      log("alice", s"""queued: "$message" (bob is offline)""")
      for r <- 4L to 10L do round(r) // alice refreshes her bundle at round 10, message included
      aliceUp = false
      log("alice", "goes offline too — now BOTH run from bundles; the backend still sees 2 writes")
      for r <- 11L to 15L do round(r)
      bobUp = true
      log("bob", "comes back online (alice is still away)")
      sb.collectAway(): Unit
      var r = 16L
      while delivered.isEmpty && r <= 30L do
        round(r)
        r += 1
      println()
      delivered match
        case Some((at, txt)) =>
          log("bob", s"""round $at: received "$txt" — from alice's bundle, while she was offline""")
          println(s"""\n  ✓ delivered with BOTH ends offline at different times: "$txt"""")
        case None => println("  ✗ not delivered within the round budget")
      println(s"""  privacy label throughout: "${provider.label}"\n""")
      delivered.exists(_._2 == message)
    finally
      channels.foreach(_.shutdownNow(): Unit)
      server.stop()

  // ---- obsd process management (mirrors the test ObsdHarness, packaged for a runnable artifact) ----

  private def findObsd(): Option[File] =
    sys.env
      .get("OBSD_BIN")
      .map(new File(_))
      .filter(f => f.exists && f.canExecute)
      .orElse {
        Seq(
          "oblivious-sidecar/target/debug/obsd",
          "../oblivious-sidecar/target/debug/obsd",
          "../../oblivious-sidecar/target/debug/obsd"
        ).map(new File(_)).find(f => f.exists && f.canExecute)
      }

  private def freePort(): Int =
    val s = new ServerSocket(0)
    try s.getLocalPort
    finally s.close()

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  private def startObsd(bin: File, port: Int, notifyKey: Array[Byte]): Process =
    val pb = new ProcessBuilder(bin.getAbsolutePath)
    pb.environment().put("OBSD_ADDR", s"127.0.0.1:$port")
    pb.environment().put("OBSD_NOTIFY_KEY", hex(notifyKey))
    // Under provider routing every user writes one frame every round and cover writes are never
    // read, so they accumulate: give the store room for the whole demo.
    pb.environment().put("OBSD_CAPACITY", "4096")
    pb.redirectOutput(ProcessBuilder.Redirect.DISCARD) // keep demo output readable
    pb.redirectError(ProcessBuilder.Redirect.INHERIT) // but surface obsd errors
    pb.start()

  private def awaitReady(port: Int, deadlineMs: Long): Boolean =
    val end = System.nanoTime() + deadlineMs * 1000000L
    var ok = false
    while !ok && System.nanoTime() < end do
      try
        val sock = new Socket()
        sock.connect(new InetSocketAddress("127.0.0.1", port), 200)
        sock.close()
        ok = true
      catch case _: Throwable => Thread.sleep(100)
    ok
