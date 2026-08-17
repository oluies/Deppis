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
    val pb = new ProcessBuilder(bin.getAbsolutePath)
    pb.environment().put("OBSD_ADDR", s"127.0.0.1:$port")
    pb.environment().put("OBSD_NOTIFY_KEY", hex(notifyKey))
    pb.environment().put("OBSD_CAPACITY", capacity.toString)
    pb.redirectOutput(ProcessBuilder.Redirect.INHERIT)
    pb.redirectError(ProcessBuilder.Redirect.INHERIT)
    val proc = pb.start()
    try
      assert(awaitReady(port, 10000), "obsd did not become ready")
      val channel = ManagedChannelBuilder.forAddress("127.0.0.1", port).usePlaintext().build()
      try body(channel)
      finally channel.shutdownNow()
    finally
      proc.destroy()
      if !proc.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) then proc.destroyForcibly()

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

    val storePb = new ProcessBuilder(storeBin.getAbsolutePath)
    storePb.environment().put("OBSD_ADDR", s"127.0.0.1:$storePort")
    storePb.environment().put("OBSD_CAPACITY", capacity.toString)
    storePb.environment().put("OBSD_SERVICES", "store") // notify half OFF — pingd owns it
    storePb.redirectOutput(ProcessBuilder.Redirect.INHERIT)
    storePb.redirectError(ProcessBuilder.Redirect.INHERIT)

    val notifyPb = new ProcessBuilder(notifyBin.getAbsolutePath)
    notifyPb.environment().put("PINGD_ADDR", s"127.0.0.1:$notifyPort")
    notifyPb.environment().put("PINGD_NOTIFY_KEY", hex(notifyKey))
    notifyPb.redirectOutput(ProcessBuilder.Redirect.INHERIT)
    notifyPb.redirectError(ProcessBuilder.Redirect.INHERIT)

    val storeProc = storePb.start()
    val notifyProc = notifyPb.start()
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
    finally
      Seq(storeProc, notifyProc).foreach { p =>
        p.destroy()
        if !p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) then p.destroyForcibly()
      }
