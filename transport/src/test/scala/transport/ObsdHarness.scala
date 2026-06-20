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
    var ok  = false
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
  protected def withObsd(notifyKey: Array[Byte], capacity: Int = 64)(body: ManagedChannel => Unit): Unit =
    val bin  = findObsd().getOrElse(cancel("obsd binary not found; run `cargo build --bin obsd`"))
    val port = freePort()
    val pb   = new ProcessBuilder(bin.getAbsolutePath)
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
