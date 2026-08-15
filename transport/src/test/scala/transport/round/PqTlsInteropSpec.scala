package transport.round

import store.dev.DevObliviousStore
import org.scalatest.funsuite.AnyFunSuite
import java.nio.file.{Files, Path}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.sys.process.{Process, ProcessLogger}

/** Cross-stack interop for the RFC 10024 hybrid-only bind (see [[PqTls]]).
  *
  * [[PqTlsSpec]] proves what we put on the wire and [[TlsRoundServerSpec]] proves a Bouncy Castle
  * client can talk to a Bouncy Castle server — but both ends being the same implementation is
  * exactly the condition under which an interop bug stays invisible. Hybrid-only has no fallback, so
  * if BC's X25519MLKEM768 disagreed with anyone else's, every non-BC client would fail to connect
  * and nothing in this repo would notice.
  *
  * So the server is driven here by two **independent implementations**, each in its own process:
  *
  *   - **Go's `crypto/tls`** — X25519MLKEM768 enabled by default since Go 1.24. Go is preinstalled
  *     on the CI runners, so this is the pair that actually executes in CI.
  *   - **OpenSSL** — RFC 10024 support from 3.5. Today's `ubuntu-latest` still ships 3.0.x, so this
  *     pair cancels there and runs on developer machines with a current OpenSSL.
  *
  * Each pair cancels (not fails) when its tool is absent or too old: a missing tool is not a defect
  * in our code, and passing silently would be worse than skipping. Cancellations show in the summary.
  *
  * Neither peer is asked to *report* the negotiated group. Both are instead **restricted to a single
  * group**, so a completed handshake can only have used it — which sidesteps the trap that a client
  * echoing its own offered list looks identical to a negotiated one. */
class PqTlsInteropSpec extends AnyFunSuite:

  private def collect(cmd: Seq[String], cwd: Option[Path] = None): (Int, String) =
    val out = new StringBuilder
    val logger = ProcessLogger(l => out.append(l).append('\n'), l => out.append(l).append('\n'))
    val p = cwd.fold(Process(cmd))(d => Process(cmd, d.toFile))
    // The peers wait on stdin; hand them EOF so they exit once the handshake is done.
    val code = p.#<(new java.io.ByteArrayInputStream(Array.emptyByteArray)).!(logger)
    (code, out.toString)

  // -----------------------------------------------------------------------------------------
  // Peer 1: Go crypto/tls — the pair that runs in CI
  // -----------------------------------------------------------------------------------------

  /** A temp module holding a one-file Go client, if Go >= 1.24 (when `tls.X25519MLKEM768` landed). */
  private lazy val goDir: Option[Path] =
    val ok =
      try
        val v = Process(Seq("go", "version")).!!.trim // "go version go1.26.6 darwin/arm64"
        raw"go1\.(\d+)".r.findFirstMatchIn(v).exists(_.group(1).toInt >= 24)
      catch case _: Throwable => false
    Option.when(ok) {
      val dir = Files.createTempDirectory("deppis-pq-interop")
      Files.writeString(dir.resolve("go.mod"), "module pqinterop\n\ngo 1.24\n")
      // Restricted to ONE curve, so a successful handshake proves that curve was used. Stdlib only,
      // so `go run` needs no network access.
      Files.writeString(
        dir.resolve("main.go"),
        """package main
          |
          |import (
          |	"crypto/tls"
          |	"fmt"
          |	"os"
          |)
          |
          |func main() {
          |	curves := []tls.CurveID{tls.X25519MLKEM768}
          |	if len(os.Args) > 2 && os.Args[2] == "classical" {
          |		curves = []tls.CurveID{tls.X25519}
          |	}
          |	conn, err := tls.Dial("tcp", os.Args[1], &tls.Config{
          |		InsecureSkipVerify: true, // dev cert is self-signed; this asserts key agreement, not PKI
          |		MinVersion:         tls.VersionTLS13,
          |		MaxVersion:         tls.VersionTLS13,
          |		CurvePreferences:   curves,
          |		NextProtos:         []string{"h2"},
          |	})
          |	if err != nil {
          |		fmt.Println("HANDSHAKE_FAILED:", err)
          |		os.Exit(1)
          |	}
          |	defer conn.Close()
          |	fmt.Println("HANDSHAKE_OK alpn=" + conn.ConnectionState().NegotiatedProtocol)
          |}
          |""".stripMargin
      )
      dir
    }

  test("a third-party TLS stack (Go crypto/tls) completes the hybrid handshake"):
    val dir = goDir.getOrElse(cancel("no Go >= 1.24 on this machine"))
    val server = TlsRoundServer.bind(new DevObliviousStore)
    try
      val (code, text) = collect(Seq("go", "run", ".", s"localhost:${server.port}"), Some(dir))
      withClue(s"go client output:\n$text\n"):
        assert(code == 0)
        assert(text.contains("HANDSHAKE_OK alpn=h2"))
    finally server.stop()

  test(s"a Go client without ${PqTls.Group} is refused — hybrid-only has no fallback"):
    val dir = goDir.getOrElse(cancel("no Go >= 1.24 on this machine"))
    val server = TlsRoundServer.bind(new DevObliviousStore)
    try
      val (code, text) =
        collect(Seq("go", "run", ".", s"localhost:${server.port}", "classical"), Some(dir))
      withClue(s"go client output:\n$text\n"):
        assert(code != 0, "a classical-only client must NOT be able to connect")
        assert(text.contains("HANDSHAKE_FAILED"))
    finally server.stop()

  // -----------------------------------------------------------------------------------------
  // Peer 2: OpenSSL — developer machines; ubuntu-latest still ships 3.0.x
  // -----------------------------------------------------------------------------------------

  /** The first `openssl` on this machine whose TLS group list includes our hybrid group. */
  private lazy val hybridOpenssl: Option[String] =
    Seq(
      "/opt/homebrew/opt/openssl@3/bin/openssl",
      "/usr/local/opt/openssl@3/bin/openssl",
      "openssl"
    )
      .find { bin =>
        try Process(Seq(bin, "list", "-tls-groups")).!!.contains(PqTls.Group)
        catch case _: Throwable => false
      }

  test("a third-party TLS stack (OpenSSL) completes the hybrid handshake"):
    val openssl = hybridOpenssl.getOrElse(
      cancel(s"no openssl here advertises ${PqTls.Group} (needs OpenSSL >= 3.5)")
    )
    val server = TlsRoundServer.bind(new DevObliviousStore)
    try
      val (_, text) = collect(
        Seq(
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
      )
      withClue(s"openssl s_client output:\n$text\n"):
        // Assert the NEGOTIATED group, not a bare substring: openssl also echoes the groups the
        // client offered, so `contains("X25519MLKEM768")` would pass even on a downgrade.
        assert(text.contains(s"Negotiated TLS1.3 group: ${PqTls.Group}"))
        assert(text.contains("ALPN protocol: h2"))
    finally server.stop()

  test(s"an OpenSSL client without ${PqTls.Group} is refused"):
    val openssl = hybridOpenssl.getOrElse(cancel("no suitable openssl"))
    val server = TlsRoundServer.bind(new DevObliviousStore)
    try
      val (code, text) = collect(
        Seq(
          openssl,
          "s_client",
          "-connect",
          s"localhost:${server.port}",
          "-groups",
          "x25519",
          "-tls1_3"
        )
      )
      withClue(s"openssl s_client output:\n$text\n"):
        assert(code != 0, "a classical-only client must NOT be able to connect")
    finally server.stop()
