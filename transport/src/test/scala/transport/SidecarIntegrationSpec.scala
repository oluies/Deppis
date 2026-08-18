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

  // ============================================ the FATAL WIRING (exit 2, not a silent fallback)

  test("fail closed: a malformed notify key REFUSES to start rather than using the dev key"):
    // Only the pure parse (`env::hex_key_var`) was tested; the wiring that makes Malformed FATAL was
    // not, on either side. Reintroducing `.unwrap_or([0x01u8; 32])` in either `main` would leave
    // every Rust and Scala test green while the notify front silently ran on the key published in
    // this repo — ACKing every signal, delivering no bits, and forgeable by anyone. This is the only
    // test that would notice.
    val pingd =
      findPingd().getOrElse(cancel("pingd binary not found; run `cargo build --bin pingd`"))
    val obsd = findObsd().getOrElse(cancel("obsd binary not found; run `cargo build --bin obsd`"))
    val port = freePort()

    for bad <- Seq("deadbeef", "ab" * 31 + "+f", "ab" * 31 + "zz", "") do
      assert(
        exitCodeOf(pingd, Map("PINGD_ADDR" -> s"127.0.0.1:$port", "PINGD_NOTIFY_KEY" -> bad))
          .contains(2),
        s"pingd must exit(2) on PINGD_NOTIFY_KEY=`$bad`, not fall back to the dev key"
      )

    // obsd reads the notify key only when it actually serves notify, so this must be the `both` role.
    assert(
      exitCodeOf(
        obsd,
        Map(
          "OBSD_ADDR" -> s"127.0.0.1:$port",
          "OBSD_SERVICES" -> "both",
          "OBSD_NOTIFY_KEY" -> ("ab" * 31 + "+f")
        )
      ).contains(2),
      "obsd must exit(2) on a malformed OBSD_NOTIFY_KEY"
    )

  test("fail closed: an unknown OBSD_SERVICES REFUSES to start rather than defaulting to `both`"):
    // The typo that matters. Defaulting `stor` to `both` re-co-hosts the notify front and silently
    // reinstates the write-vs-bit correlation the split exists to remove.
    val obsd = findObsd().getOrElse(cancel("obsd binary not found; run `cargo build --bin obsd`"))
    val port = freePort()
    for bad <- Seq("stor", "STORE", "store ", "notify", "") do
      assert(
        exitCodeOf(obsd, Map("OBSD_ADDR" -> s"127.0.0.1:$port", "OBSD_SERVICES" -> bad))
          .contains(2),
        s"obsd must exit(2) on OBSD_SERVICES=`$bad`, not default to `both`"
      )

  test("the split role SERVES, and stays silent about the notify key it never uses"):
    // Both halves of the name are asserted, which the previous revision did not manage: it inherited
    // the child's stderr (so nothing could look at the warning) and treated "did not exit within 2s"
    // as success (equally satisfied by a process that hung before binding). Now the harness waits for
    // the port to ACCEPT and captures stderr, so hoisting the dev-key `eprintln!` back above the role
    // check — reinstating a warning that fires in the CORRECT deployment, which is how operators
    // learn to ignore warnings — fails here.
    val obsd = findObsd().getOrElse(cancel("obsd binary not found; run `cargo build --bin obsd`"))
    val port = freePort()
    withRunningSidecar(
      obsd,
      Map("OBSD_ADDR" -> s"127.0.0.1:$port", "OBSD_SERVICES" -> "store"),
      port
    ) { err =>
      assert(
        !err.contains("using the DEV key"),
        s"the store role must not warn about a notify key it never constructs:\n$err"
      )
      assert(err.contains("ObliviousStore ONLY"), s"expected the store-only banner:\n$err")
    }

  test("the split role NOTICES a notify key that is set but inert, and still starts"):
    // Converting a co-hosted unit file to the split topology means keeping OBSD_NOTIFY_KEY while
    // adding OBSD_SERVICES=store. The key becomes inert — pingd owns it now — and silence there is a
    // config drift nobody sees. Non-fatal by design: an ignored key is untidy, not unsafe, because
    // this role never opens a token. Note the key here is deliberately MALFORMED as well, pinning
    // that the store role does not even parse it.
    val obsd = findObsd().getOrElse(cancel("obsd binary not found; run `cargo build --bin obsd`"))
    val port = freePort()
    withRunningSidecar(
      obsd,
      Map(
        "OBSD_ADDR" -> s"127.0.0.1:$port",
        "OBSD_SERVICES" -> "store",
        "OBSD_NOTIFY_KEY" -> "not-a-key"
      ),
      port
    ) { err =>
      assert(
        err.contains("IGNORED in the store role"),
        s"a set-but-inert OBSD_NOTIFY_KEY must be reported, not silently dropped:\n$err"
      )
    }

  test("the `both` role DOES warn when it falls back to the dev notify key"):
    // The mirror of the suppression above: the label discipline only works if the warning is absent
    // where it is noise AND present where it matters. Without this, "suppress the warning" could be
    // satisfied by deleting it outright.
    val obsd = findObsd().getOrElse(cancel("obsd binary not found; run `cargo build --bin obsd`"))
    val port = freePort()
    withRunningSidecar(
      obsd,
      Map("OBSD_ADDR" -> s"127.0.0.1:$port", "OBSD_SERVICES" -> "both"),
      port
    ) { err =>
      assert(
        err.contains("using the DEV key"),
        s"the co-hosted role must announce the dev-key fallback:\n$err"
      )
    }
