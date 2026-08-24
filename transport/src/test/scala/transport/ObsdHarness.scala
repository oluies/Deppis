package transport

import io.grpc.{ManagedChannel, ManagedChannelBuilder}
import java.io.File
import java.net.{InetSocketAddress, ServerSocket, Socket}
import org.scalatest.Assertions

/** Shared test harness that spawns the real Rust `obsd` sidecar and hands a gRPC channel to it.
  *
  * Opt-in: if the `obsd` binary isn't found (e.g. CI's pure-JVM job, which has no cargo), tests that
  * use [[withObsd]] `cancel` rather than fail. Build it with `cargo build --bin obsd` (or set
  * `OBSD_BIN`). Mixed into a `Suite` so `cancel` is in scope. */
trait ObsdHarness extends Assertions:

  protected def findObsd(): Option[File] =
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

  protected def freePort(): Int =
    val s = new ServerSocket(0)
    try s.getLocalPort
    finally s.close()

  protected def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  protected def awaitReady(port: Int, deadlineMs: Long): Boolean =
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

  /** Start obsd on a free port with a known notify key + capacity; run `body` with a channel to it.
    * Inherits the child's stdout/stderr (avoids a pipe-buffer deadlock and surfaces obsd logs), and
    * tears down with a bounded wait + forcible kill. */
  protected def withObsd(notifyKey: Array[Byte], capacity: Int = 64)(
      body: ManagedChannel => Unit
  ): Unit =
    val bin = findObsd().getOrElse(cancel("obsd binary not found; run `cargo build --bin obsd`"))
    val port = freePort()
    // No OBSD_SERVICES here: `spawn` scrubs the namespace, so the child falls through to the `both`
    // default that these two round-trip tests need, regardless of what the developer has exported.
    val proc = spawn(
      bin,
      Map(
        "OBSD_ADDR" -> s"127.0.0.1:$port",
        "OBSD_NOTIFY_KEY" -> hex(notifyKey),
        "OBSD_CAPACITY" -> capacity.toString
      ),
      None
    )
    try
      assert(awaitReady(port, 10000), "obsd did not become ready")
      val channel = ManagedChannelBuilder.forAddress("127.0.0.1", port).usePlaintext().build()
      try body(channel)
      finally channel.shutdownNow()
    finally teardown(proc)

  protected def findPingd(): Option[File] =
    sys.env
      .get("PINGD_BIN")
      .map(new File(_))
      .filter(f => f.exists && f.canExecute)
      .orElse {
        Seq(
          "oblivious-sidecar/target/debug/pingd",
          "../oblivious-sidecar/target/debug/pingd",
          "../../oblivious-sidecar/target/debug/pingd"
        ).map(new File(_)).find(f => f.exists && f.canExecute)
      }

  /** Spawn `bin` with a child environment defined ENTIRELY by `env`.
    *
    * `ProcessBuilder.environment()` starts as a copy of the *sbt JVM's* environment, and these tests
    * are the first that depend on what is ABSENT from it. With `OBSD_NOTIFY_KEY` exported in a
    * developer's shell, "the `both` role DOES warn" fails (the key parses, so there is no fallback to
    * announce) and "a notify key that is set but inert" passes for the wrong reason; an exported
    * `OBSD_SERVICES=store` turns the notify round-trip test into a confusing failure and
    * `OBSD_SERVICES=stor` kills every `withObsd` test on exit(2). So the whole sidecar namespace is
    * dropped from the inherited copy before `env` is applied — a spawn here means what it says. */
  private def spawn(bin: File, env: Map[String, String], errTo: Option[File]): Process =
    val pb = new ProcessBuilder(bin.getAbsolutePath)
    pb.environment().keySet.removeIf(k => k.startsWith("OBSD_") || k.startsWith("PINGD_")): Unit
    env.foreach { case (k, v) => pb.environment().put(k, v) }
    pb.redirectOutput(ProcessBuilder.Redirect.INHERIT)
    pb.redirectError(errTo.fold(ProcessBuilder.Redirect.INHERIT)(ProcessBuilder.Redirect.to))
    pb.start()

  private def teardown(proc: Process): Unit =
    proc.destroy()
    if !proc.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) then proc.destroyForcibly(): Unit

  /** [[spawn]] with stderr CAPTURED to a temp file rather than inherited, handing `body` the process
    * and a reader for the stderr so far, and always tearing the process down.
    *
    * Capture is the point: an earlier revision inherited both streams, which made it impossible to
    * assert on the child's output at all — so the test named "does NOT warn about ... a key it never
    * uses" asserted only the "does not die" half, and hoisting the dev-key `eprintln!` back above the
    * role check would have reinstated the spurious warning with every test still green.
    *
    * [[runSidecar]] and [[withRunningSidecar]] are both built on this rather than each carrying their
    * own copy of temp-file + ProcessBuilder + teardown; two copies drift, and a fix to stderr capture
    * or to teardown should not have to be made twice. */
  private def withCaptured[A](bin: File, env: Map[String, String])(
      body: (Process, () => String) => A
  ): A =
    val errFile = java.io.File.createTempFile("sidecar-stderr", ".log")
    errFile.deleteOnExit()
    val proc = spawn(bin, env, Some(errFile))
    try body(proc, () => new String(java.nio.file.Files.readAllBytes(errFile.toPath), "UTF-8"))
    finally
      teardown(proc)
      errFile.delete(): Unit

  /** Spawn a sidecar binary with `env` and report how it behaved: the exit code if it terminated
    * within `waitMs`, or `None` if it was still running (i.e. it started rather than refusing to),
    * plus its stderr. Returns `(exitCode, stderr)`.
    *
    * This exists because the FATAL WIRING had no automated test on either side — only the pure parse
    * did. Reintroducing `hex_key_var(..).unwrap_or([0x01u8; 32])` in either `main` would leave every
    * Rust and Scala test green, which is the same gap the `serve_notify` extraction was done to
    * close. A spawn-and-check-the-exit-code case is the only place that wiring is observable. */
  protected def runSidecar(
      bin: File,
      env: Map[String, String],
      waitMs: Long = 5000
  ): (Option[Int], String) =
    withCaptured(bin, env) { (proc, stderr) =>
      val code =
        if proc.waitFor(waitMs, java.util.concurrent.TimeUnit.MILLISECONDS) then
          Some(proc.exitValue())
        else None
      (code, stderr())
    }

  /** [[runSidecar]] when only the exit code matters. */
  protected def exitCodeOf(bin: File, env: Map[String, String], waitMs: Long = 5000): Option[Int] =
    runSidecar(bin, env, waitMs)._1

  /** Spawn `bin`, wait for it to ACCEPT CONNECTIONS on `port`, and run `body` with its stderr so far.
    * Fails if it exits or never binds — "did not exit within N seconds" is not evidence that a server
    * came up, since it is equally satisfied by a process that hung before binding.
    *
    * NOTE there is deliberately no "nothing is listening after it refused to start" assertion
    * anywhere in this harness. A terminated process cannot hold a listening socket, so such a check
    * is tautological given the exit code, and its only reachable failure is an unrelated process
    * grabbing the ephemeral port (`freePort` closes before returning) — a pure flake that would then
    * report the false accusation "the binary left a listener behind". */
  protected def withRunningSidecar(bin: File, env: Map[String, String], port: Int)(
      body: String => Unit
  ): Unit =
    withCaptured(bin, env) { (proc, stderr) =>
      assert(awaitReady(port, 8000), s"${bin.getName} never accepted a connection on $port")
      assert(proc.isAlive, s"${bin.getName} exited instead of serving")
      body(stderr())
    }

  /** The PRODUCTION topology: the PONG store and the PING notify front as two SEPARATE processes —
    * `obsd` with `OBSD_SERVICES=store`, and `pingd`. Hands `body` a channel to each.
    *
    * This is what the split is for. Co-hosting both roles lets one process join "a write landed at
    * round r" with "label L's bit was set at round r" and re-identify the receiver of every real
    * frame, which no amount of obliviousness inside either service repairs. Two processes are
    * NECESSARY but not SUFFICIENT — on one host under one operator the join is still trivial — so
    * this harness proves the topology works, not that it is private. See `pingd.rs`. */
  protected def withSplitFronts(notifyKey: Array[Byte], capacity: Int = 64)(
      body: (ManagedChannel, ManagedChannel) => Unit
  ): Unit =
    val storeBin =
      findObsd().getOrElse(cancel("obsd binary not found; run `cargo build --bin obsd`"))
    val notifyBin =
      findPingd().getOrElse(cancel("pingd binary not found; run `cargo build --bin pingd`"))
    // Both sockets are held open until BOTH ports are chosen. `freePort()` binds, reads, and closes
    // before returning, so two sequential calls can hand back the SAME port — and that failure is
    // silent in the worst way: obsd binds it first, pingd's `serve` dies with AddrInUse, yet
    // `awaitReady(notifyPort)` still connects (to obsd), so the first split test fails confusingly
    // and the second one PASSES for the wrong reason (obsd has no notify service either).
    val (storePort, notifyPort) =
      val a = new ServerSocket(0)
      val b = new ServerSocket(0)
      try (a.getLocalPort, b.getLocalPort)
      finally { a.close(); b.close() }
    assert(storePort != notifyPort, "port allocation collided")

    val storeProc = spawn(
      storeBin,
      Map(
        "OBSD_ADDR" -> s"127.0.0.1:$storePort",
        "OBSD_CAPACITY" -> capacity.toString,
        "OBSD_SERVICES" -> "store" // notify half OFF — pingd owns it
      ),
      None
    )
    val notifyProc = spawn(
      notifyBin,
      Map("PINGD_ADDR" -> s"127.0.0.1:$notifyPort", "PINGD_NOTIFY_KEY" -> hex(notifyKey)),
      None
    )
    try
      assert(awaitReady(storePort, 10000), "obsd (store-only) did not become ready")
      assert(awaitReady(notifyPort, 10000), "pingd did not become ready")
      val storeCh = ManagedChannelBuilder.forAddress("127.0.0.1", storePort).usePlaintext().build()
      val notifyCh =
        ManagedChannelBuilder.forAddress("127.0.0.1", notifyPort).usePlaintext().build()
      try body(storeCh, notifyCh)
      finally
        storeCh.shutdownNow()
        notifyCh.shutdownNow()
    finally Seq(storeProc, notifyProc).foreach(teardown)
