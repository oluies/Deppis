package transport

import metadatamessenger.store.v1.{store as spb}
import metadatamessenger.notify.v1.{notify as npb}
import crypto.Crypto
import frame.Frame
import ping.DevNotificationServer
import com.google.protobuf.ByteString
import io.grpc.{ManagedChannel, ManagedChannelBuilder}
import java.io.File
import java.net.{InetSocketAddress, Socket, ServerSocket}
import org.scalatest.funsuite.AnyFunSuite

/** Cross-process integration: spins up the real Rust `obsd` sidecar and drives the Scala
  * enclave-target fronts against it over actual gRPC — proving the Scala client ↔ Rust server
  * interop (proto wire format, found-tag, AEAD round-binding) end to end.
  *
  * Opt-in: if the `obsd` binary isn't found (e.g. CI's pure-JVM job, which has no cargo), the tests
  * `cancel` rather than fail. Build it with `cargo build --bin obsd` (or set `OBSD_BIN`). */
class SidecarIntegrationSpec extends AnyFunSuite:

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

  private def awaitReady(port: Int, deadlineMs: Long): Boolean =
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

  /** Start obsd on a free port with a known notify key; run `body` with a channel to it. */
  private def withObsd(notifyKey: Array[Byte])(body: ManagedChannel => Unit): Unit =
    val bin  = findObsd().getOrElse(cancel("obsd binary not found; run `cargo build --bin obsd`"))
    val port = freePort()
    val pb   = new ProcessBuilder(bin.getAbsolutePath)
    pb.environment().put("OBSD_ADDR", s"127.0.0.1:$port")
    pb.environment().put("OBSD_NOTIFY_KEY", hex(notifyKey))
    pb.environment().put("OBSD_CAPACITY", "64")
    // Inherit the child's stdout/stderr: avoids a pipe-buffer deadlock (nothing would drain a
    // buffered pipe) and surfaces obsd's logs to the test console on failure.
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

  test("store: write then read over real gRPC to obsd (found-tag, single-use)"):
    withObsd(Array.fill(Crypto.KeyBytes)(0x11.toByte)) { channel =>
      val store = new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested = false)
      val token = Array.tabulate(32)(_.toByte)            // 32-byte retrieval token
      val frame = Frame.pad("over the wire".getBytes).toOption.get
      assert(store.write(token, frame).isRight)
      assert(store.read(token).toOption.flatten.exists(_.sameElements(frame))) // hit
      assert(store.read(token).toOption.flatten.isEmpty)                       // single-use
    }

  test("notify: Scala-sealed token signaled to obsd, digest fetched back (AEAD + round binding)"):
    val key = Array.tabulate(Crypto.KeyBytes)(i => (i * 7).toByte)
    withObsd(key) { channel =>
      val receiver = DevNotificationServer(key) // seals tokens with the same key obsd opens with
      val client   = new EnclaveNotificationClient(npb.NotificationServiceGrpc.blockingStub(channel), attested = false)
      val label    = "alice".getBytes
      assert(client.signal(1L, receiver.issueToken(1L, 5, label)).isRight)
      val digest = client.fetchDigest(1L, label).toOption.get
      assert((digest(5 >> 3) & (1 << (5 & 7))) != 0) // bit 5 set
      // round binding: a token bound to round 1 signaled into round 2 sets nothing
      assert(client.signal(2L, receiver.issueToken(1L, 9, label)).isRight)
      val d2 = client.fetchDigest(2L, label).toOption.get
      assert(d2.forall(_ == 0))
    }
