package transport

import io.grpc.{ManagedChannel, ManagedChannelBuilder}
import java.io.File
import java.net.{InetSocketAddress, ServerSocket, Socket}
import java.util.concurrent.TimeUnit
import metadatamessenger.store.v1.{store as spb}
import metadatamessenger.notify.v1.{notify as npb}
import engine.{BuddyRole, Engine, EngineEvent, KeySchedule, NotifyDigest}
import handshake.Handshake
import ping.DevNotificationServer
import crypto.Crypto

/** Headless runnable demo (the "core" prototype). Two independent client engines — Alice and Bob —
  * pair out of band, then Alice sends Bob a message that is delivered through the **real Rust `obsd`
  * sidecar**, the same path the cross-process tests exercise (`TwoPartyE2ESpec`,
  * `EngineBackendE2ESpec`). Every round each client writes exactly one frame (real or cover) and
  * reads exactly once, so an observer cannot tell an active round from an idle one (FR-012).
  *
  * THIS IS A DEV BUILD: the dev store/notify provide NO access-pattern privacy and the run is NOT
  * attested, so it reports the `DEV, NO METADATA PRIVACY` label (Constitution IV). The demo also
  * plays the PING aggregation front (sealing Bob's notify bit when Alice sends a real frame) — that
  * bridge is not yet a standalone process; it is clearly marked below.
  *
  * Run: build obsd first (`cargo build --bin obsd` in `oblivious-sidecar/`), then
  *   `sbt "transport/runMain transport.DeppisDemo"`
  * Point `OBSD_BIN` at the binary if it is not on a default relative path. */
object DeppisDemo:

  private def log(who: String, msg: String): Unit = println(f"  [$who%-5s] $msg")

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
    * it against the test `ObsdHarness`. */
  def run(channel: ManagedChannel, notifyKey: Array[Byte]): Boolean =
    val storeStub = spb.ObliviousStoreGrpc.blockingStub(channel)
    val notifyStub = npb.NotificationServiceGrpc.blockingStub(channel)

    val aliceLabel = "alice-client".getBytes
    val bobLabel = "bob-client".getBytes
    def front(): GrpcRoundTransport =
      new GrpcRoundTransport(
        new EnclaveObliviousStore(storeStub, attested = false),
        new EnclaveNotificationClient(notifyStub, attested = false)
      )
    val alice = Engine(Some(front()), clientLabel = aliceLabel)
    val bob = Engine(Some(front()), clientLabel = bobLabel)

    println("\n== Deppis metadata-private messenger — headless demo ==")
    val ps = alice.privacyStatus
    println(
      s"""  backend=${ps.backend}  metadataPrivate=${ps.metadataPrivate}  label="${ps.label}"\n"""
    )

    // 1) Out-of-band pairing: same shared secret, opposite roles; safety numbers compared by hand.
    val secret = "meet-me-at-the-old-bridge".getBytes
    val a = alice.addBuddy(secret, BuddyRole.Initiator).toOption.get
    alice.confirmBuddy(a.pairId, matched = true); alice.drainEvents()
    val b = bob.addBuddy(secret, BuddyRole.Responder).toOption.get
    bob.confirmBuddy(b.pairId, matched = true); bob.drainEvents()
    log("alice", s"paired with bob — safetyNumber ${a.safetyNumber}")
    log("bob", s"paired with alice — safetyNumber ${b.safetyNumber}")
    if a.safetyNumber != b.safetyNumber then
      println("  ✗ safety numbers differ — pairing would be rejected")
      return false
    println("  ✓ safety numbers match → out-of-band verification succeeds\n")

    // The PING aggregation front (stand-in): when Alice sends a real frame, it SEALS Bob's per-buddy
    // bit (a token bound to the round) and signals it to obsd over gRPC — exactly as a PONG-side
    // front would. `sealer` only mints the token (it shares obsd's notify key); `pingSignal` is the
    // actual gRPC call into obsd, whose digest Bob's engine then reads. This bridge is not yet a
    // standalone process.
    val sealer = DevNotificationServer(notifyKey)
    val pingSignal = new EnclaveNotificationClient(notifyStub, attested = false)
    val pairKey = Handshake.init(secret).pairKey
    // Bob's engine derives the notify bit from the addressing root (the forward-secrecy root split).
    val bobBit = NotifyDigest.bit(KeySchedule.addrKey(pairKey))

    // 2) Alice queues a message.
    val message = "see you at dusk"
    alice.sendMessage(a.pairId, message)
    log("alice", s"""queued message: "$message"""")
    println("\n  driving rounds — each client writes one frame (real or cover) and reads once:\n")

    // 3) Run rounds until delivered or the budget is spent. Bob also writes a cover frame each round
    //    (uniform traffic, FR-012) — we narrate the Alice→Bob direction.
    var delivered = false
    var round = 1L
    val maxRounds = 5L
    while !delivered && round <= maxRounds do
      val ad = alice.tick(round).toOption.get
      val aliceReal = !ad.carrier
      // DEV stand-in only: signalling obsd ONLY on real rounds makes the notify RPC volume depend on
      // whether a real message was sent — an active-vs-idle distinguisher at the front. The engine's
      // own store traffic is already uniform; the REAL PONG/PING front MUST likewise decouple signal
      // timing/volume from real-message presence (aggregation + cover signalling). Safe here only
      // because the whole run is DEV, NO METADATA PRIVACY.
      if aliceReal then pingSignal.signal(round, sealer.issueToken(round, bobBit, bobLabel))
      log(
        "alice",
        f"round $round: wrote ${if aliceReal then "REAL  frame" else "cover frame"} (256B, indistinguishable)"
      )

      bob.tick(round)
      val evs = bob.drainEvents()
      val gotNotify = evs.exists(_.isInstanceOf[EngineEvent.Notified])
      val gotMsg = evs.collectFirst { case m: EngineEvent.MessageReceived => m }
      if gotNotify then
        log("bob", f"round $round: notified — mail waiting (sender identity NOT revealed)")
      gotMsg match
        case Some(EngineEvent.MessageReceived(pid, txt, _)) =>
          log("bob", s"""round $round: retrieved from $pid: "$txt"""")
          delivered = true
        case _ =>
          if !gotNotify then log("bob", f"round $round: read a cover frame — nothing for me")
      round += 1

    println()
    if delivered then
      println(s"""  ✓ delivered end-to-end through the real obsd sidecar: "$message"""")
    else println("  ✗ not delivered within the round budget")
    println(s"""  privacy label throughout: "${alice.privacyStatus.label}"\n""")
    delivered

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
    pb.environment().put("OBSD_CAPACITY", "64")
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
