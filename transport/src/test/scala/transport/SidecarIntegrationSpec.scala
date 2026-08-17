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

  // ============================================ the SPLIT topology (Phase C, ARCHITECTURE.md §6)

  test("split fronts: a full round works with the store and the notify front in TWO processes"):
    // The PING/PONG split is a TRUST-DOMAIN split. Co-hosting lets one process join "a write landed
    // at round r" with "label L's bit was set at round r" and re-identify the receiver of every real
    // frame — a leak in the JOIN that obliviousness inside either service cannot repair. This drives
    // the real deployment shape: obsd with the notify half OFF, plus pingd.
    val key = Array.tabulate(Crypto.KeyBytes)(i => (i * 11).toByte)
    withSplitFronts(key) { (storeCh, notifyCh) =>
      val store =
        new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(storeCh), attested = false)
      val notify = new EnclaveNotificationClient(
        npb.NotificationServiceGrpc.blockingStub(notifyCh),
        attested = false
      )
      val sealer = DevNotificationServer(key)
      val label = "bob".getBytes
      val token = Array.tabulate(32)(i => (i * 3).toByte)
      val wire = Frame.pad("across two processes".getBytes).toOption.get

      // PONG half: the frame lands in the store process.
      assert(store.write(token, wire).isRight)
      // PING half: the bit lands in the notify process, which never saw the write.
      assert(notify.signal(7L, sealer.issueToken(7L, 3, label)).isRight)
      val digest = notify.fetchDigest(7L, label).toOption.get
      assert((digest(3 >> 3) & (1 << (3 & 7))) != 0, "the notify process must have set bit 3")
      // And the receiver still collects its frame from the store process.
      assert(store.read(token).toOption.flatten.exists(_.sameElements(wire)))
      assert(store.read(token).toOption.flatten.isEmpty, "single-use still holds across the split")
    }

  test("split fronts: the STORE process serves no notify service at all"):
    // The assertion that gives the split its teeth. If obsd kept answering NotificationService while
    // pingd also ran, a deployment could believe it had separated the roles while the store process
    // still saw every signal — the co-hosting leak, reinstated silently. `OBSD_SERVICES=store` must
    // actually remove the service, not merely stop advertising it.
    //
    // Asserted on the RAW STUB against the exact status code, not through
    // `EnclaveNotificationClient`. That front collapses every NonFatal to `Left`, so an `isLeft`
    // check is satisfied just as well by obsd having died right after `awaitReady`'s TCP connect, by
    // a channel-shutdown race, or by a deadline — none of which say anything about which services
    // are registered. UNIMPLEMENTED is the one code that means "this process does not serve that
    // service".
    val key = Array.tabulate(Crypto.KeyBytes)(i => (i * 13).toByte)
    withSplitFronts(key) { (storeCh, _) =>
      val store =
        new EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(storeCh), attested = false)
      // LIVENESS CONTROL first: prove the store process is up and answering on THIS channel, so a
      // dead process fails the test here instead of passing it below.
      val token = Array.tabulate(32)(i => (i * 5).toByte)
      val wire = Frame.pad("liveness".getBytes).toOption.get
      assert(store.write(token, wire).isRight, "the store process must be alive and serving PONG")
      assert(store.read(token).toOption.flatten.exists(_.sameElements(wire)))

      val rawNotify = npb.NotificationServiceGrpc.blockingStub(storeCh)
      val sealer = DevNotificationServer(key)

      def codeOf(call: => Any): io.grpc.Status.Code =
        try
          call
          fail("the store process ANSWERED a notify RPC — the roles are still co-hosted")
        catch case e: io.grpc.StatusRuntimeException => e.getStatus.getCode

      val signalCode = codeOf(
        rawNotify.signal(
          npb.SignalRequest(
            roundId = 1L,
            sealedToken = com.google.protobuf.ByteString.copyFrom(
              sealer.issueToken(1L, 5, "bob".getBytes)
            )
          )
        )
      )
      assert(
        signalCode == io.grpc.Status.Code.UNIMPLEMENTED,
        s"expected UNIMPLEMENTED from the store process, got $signalCode"
      )

      val digestCode = codeOf(
        rawNotify.fetchDigest(
          npb.FetchDigestRequest(
            roundId = 1L,
            clientLabel = com.google.protobuf.ByteString.copyFrom("bob".getBytes)
          )
        )
      )
      assert(
        digestCode == io.grpc.Status.Code.UNIMPLEMENTED,
        s"expected UNIMPLEMENTED from the store process, got $digestCode"
      )
    }
