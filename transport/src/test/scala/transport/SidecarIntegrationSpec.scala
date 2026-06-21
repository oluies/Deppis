package transport

import metadatamessenger.store.v1.{store as spb}
import metadatamessenger.notify.v1.{notify as npb}
import crypto.Crypto
import frame.Frame
import ping.DevNotificationServer
import org.scalatest.funsuite.AnyFunSuite

/** Cross-process integration: spins up the real Rust `obsd` sidecar (via [[ObsdHarness]]) and drives
  * the Scala enclave-target fronts against it over actual gRPC — proving the Scala client ↔ Rust
  * server interop (proto wire format, found-tag, AEAD round-binding) end to end. */
class SidecarIntegrationSpec extends AnyFunSuite with ObsdHarness:

  test("store: write then read over real gRPC to obsd (found-tag, single-use)"):
    withObsd(Array.fill(Crypto.KeyBytes)(0x11.toByte)) { channel =>
      val store =
        new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested = false)
      val token = Array.tabulate(32)(_.toByte) // 32-byte retrieval token
      val frame = Frame.pad("over the wire".getBytes).toOption.get
      assert(store.write(token, frame).isRight)
      assert(store.read(token).toOption.flatten.exists(_.sameElements(frame))) // hit
      assert(store.read(token).toOption.flatten.isEmpty) // single-use
    }

  test("notify: Scala-sealed token signaled to obsd, digest fetched back (AEAD + round binding)"):
    val key = Array.tabulate(Crypto.KeyBytes)(i => (i * 7).toByte)
    withObsd(key) { channel =>
      val receiver = DevNotificationServer(key) // seals tokens with the same key obsd opens with
      val client = new EnclaveNotificationClient(
        npb.NotificationServiceGrpc.blockingStub(channel),
        attested = false
      )
      val label = "alice".getBytes
      assert(client.signal(1L, receiver.issueToken(1L, 5, label)).isRight)
      val digest = client.fetchDigest(1L, label).toOption.get
      assert((digest(5 >> 3) & (1 << (5 & 7))) != 0) // bit 5 set
      // round binding: a token bound to round 1 signaled into round 2 sets nothing
      assert(client.signal(2L, receiver.issueToken(1L, 9, label)).isRight)
      val d2 = client.fetchDigest(2L, label).toOption.get
      assert(d2.forall(_ == 0))
    }
