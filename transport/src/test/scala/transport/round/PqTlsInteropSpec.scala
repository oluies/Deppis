package transport.round

import store.dev.DevObliviousStore
import org.scalatest.funsuite.AnyFunSuite
import scala.concurrent.ExecutionContext.Implicits.global
import scala.sys.process.{Process, ProcessLogger}

/** Cross-stack interop for the RFC 10024 hybrid-only bind (see [[PqTls]]).
  *
  * [[PqTlsSpec]] proves what we put on the wire and [[TlsRoundServerSpec]] proves a Bouncy Castle
  * client can talk to a Bouncy Castle server — but both ends being the same implementation is
  * exactly the condition under which an interop problem stays invisible. Hybrid-only has no
  * fallback, so if BC's X25519MLKEM768 disagreed with anyone else's, every non-BC client would fail
  * to connect and nothing in this repo would notice.
  *
  * So this drives the real server with a genuinely independent stack: the `openssl` binary. OpenSSL
  * implements RFC 10024 from 3.5 onward; older ones (Ubuntu 24.04 ships 3.0.x) do not, and this test
  * **cancels** rather than fails there — a missing tool is not a defect in our code, and quietly
  * passing would be worse than skipping. */
class PqTlsInteropSpec extends AnyFunSuite:

  /** The first `openssl` on this machine whose TLS group list includes our hybrid group. */
  private lazy val hybridOpenssl: Option[String] =
    val candidates = Seq(
      "/opt/homebrew/opt/openssl@3/bin/openssl",
      "/usr/local/opt/openssl@3/bin/openssl",
      "openssl"
    )
    candidates.find { bin =>
      try Process(Seq(bin, "list", "-tls-groups")).!!.contains(PqTls.Group)
      catch case _: Throwable => false
    }

  test("a third-party TLS stack (OpenSSL) completes the hybrid handshake against TlsRoundServer"):
    val openssl = hybridOpenssl.getOrElse(
      cancel(s"no openssl on this machine advertises ${PqTls.Group} (needs OpenSSL >= 3.5)")
    )
    val server = TlsRoundServer.bind(new DevObliviousStore)
    try
      val out = new StringBuilder
      val logger = ProcessLogger(l => out.append(l).append('\n'), l => out.append(l).append('\n'))
      // `-groups` restricts the client to the hybrid group, so a completed handshake can only have
      // used it. The dev cert is self-signed, so a verify error is expected and irrelevant here —
      // this asserts on key agreement, not on the PKI (which TlsRoundServerSpec covers).
      val cmd = Seq(
        openssl,
        "s_client",
        "-connect",
        s"localhost:${server.port}",
        "-groups",
        PqTls.Group,
        "-tls1_3",
        "-alpn",
        "h2"
      )
      // s_client waits on stdin; feed it EOF so it disconnects once the handshake is done.
      Process(cmd).#<(new java.io.ByteArrayInputStream(Array.emptyByteArray)).!(logger)
      val text = out.toString

      withClue(s"openssl s_client output:\n$text\n"):
        // Assert on the NEGOTIATED group, not a bare substring: openssl also echoes the groups the
        // client offered, so `contains("X25519MLKEM768")` alone would pass even on a downgrade.
        // This exact line is emitted only for the group the handshake actually agreed on.
        assert(text.contains(s"Negotiated TLS1.3 group: ${PqTls.Group}"))
        assert(text.contains("ALPN protocol: h2"))
    finally server.stop()

  test(s"a client without ${PqTls.Group} is refused — the hybrid-only bind has no fallback"):
    val openssl = hybridOpenssl.getOrElse(cancel("no suitable openssl"))
    val server = TlsRoundServer.bind(new DevObliviousStore)
    try
      val out = new StringBuilder
      val logger = ProcessLogger(l => out.append(l).append('\n'), l => out.append(l).append('\n'))
      // Classical-only client: under RFC 10024 hybrid-only there is deliberately nothing to agree on.
      val cmd =
        Seq(
          openssl,
          "s_client",
          "-connect",
          s"localhost:${server.port}",
          "-groups",
          "x25519",
          "-tls1_3"
        )
      val code =
        Process(cmd).#<(new java.io.ByteArrayInputStream(Array.emptyByteArray)).!(logger)
      withClue(s"openssl s_client output:\n${out.toString}\n"):
        assert(code != 0, "a classical-only client must NOT be able to connect")
    finally server.stop()
