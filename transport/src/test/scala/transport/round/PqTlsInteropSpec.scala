package transport.round

import store.dev.DevObliviousStore
import org.scalatest.funsuite.AnyFunSuite
import java.io.ByteArrayInputStream
import java.nio.file.{Files, Path}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.*
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

  /** Every peer is a child process reached over a socket, so *every* way this can go wrong ends in a
    * blocked read rather than an error. A stalled handshake is not hypothetical here either: it is
    * the documented failure mode for oversized PQ ClientHellos ([[PqTls]]), and `s_client` in
    * particular holds the connection open by design. Unbounded, that hangs the sbt run with no
    * output, so the peer is bounded and killed. */
  private val PeerTimeout = 60.seconds

  /** Run `cmd` to completion under [[PeerTimeout]], returning (exit code, merged stdout+stderr).
    * StringBuffer, not StringBuilder: the logger callbacks run on process-reader threads. */
  private def collect(cmd: Seq[String], cwd: Option[Path] = None): (Int, String) =
    val out = new StringBuffer
    val logger = ProcessLogger(l => { out.append(l).append('\n'); () })
    val builder = cwd.fold(Process(cmd))(d => Process(cmd, d.toFile))
    // Empty stdin so peers that read from it (s_client) see EOF and exit after the handshake.
    val p = builder.#<(new ByteArrayInputStream(Array.emptyByteArray)).run(logger)
    val deadline = System.nanoTime() + PeerTimeout.toNanos
    while p.isAlive() && System.nanoTime() < deadline do Thread.sleep(50)
    if p.isAlive() then
      p.destroy()
      fail(s"peer did not exit within $PeerTimeout: ${cmd.mkString(" ")}\noutput so far:\n$out")
    (p.exitValue(), out.toString)

  /** A refusal must be a TLS-level one. Exit status alone is not enough: a peer exits non-zero for a
    * bad argument, a refused connection, or a crash, so asserting only on the code would keep
    * passing after the no-fallback property it guards had silently stopped holding. */
  private def assertKeyAgreementRefusal(code: Int, text: String): Unit =
    assert(code != 0, s"a classical-only client must NOT be able to connect. Output:\n$text")
    val t = text.toLowerCase
    assert(
      t.contains("handshake failure") || t.contains("alert") || t.contains("handshake_failed"),
      s"expected a TLS handshake refusal, not some other failure. Output:\n$text"
    )

  private def withServer[A](body: TlsRoundServer => A): A =
    val server = TlsRoundServer.bind(new DevObliviousStore)
    try body(server)
    finally server.stop()

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

  private def goClient(server: TlsRoundServer, dir: Path, classical: Boolean): (Int, String) =
    val args =
      Seq("go", "run", ".", s"localhost:${server.port}") ++ Option.when(classical)("classical")
    collect(args, Some(dir))

  test("a third-party TLS stack (Go crypto/tls) completes the hybrid handshake"):
    val dir = goDir.getOrElse(cancel("no Go >= 1.24 on this machine"))
    withServer { server =>
      val (code, text) = goClient(server, dir, classical = false)
      withClue(s"go client output:\n$text\n"):
        assert(code == 0)
        assert(text.contains("HANDSHAKE_OK alpn=h2"))
    }

  test(s"a Go client without ${PqTls.Group} is refused — hybrid-only has no fallback"):
    val dir = goDir.getOrElse(cancel("no Go >= 1.24 on this machine"))
    withServer { server =>
      val (code, text) = goClient(server, dir, classical = true)
      assertKeyAgreementRefusal(code, text)
    }

  // -----------------------------------------------------------------------------------------
  // Peer 2: OpenSSL — developer machines; ubuntu-latest still ships 3.0.x
  // -----------------------------------------------------------------------------------------

  /** The first `openssl` on this machine whose TLS group list includes our hybrid group. */
  private lazy val hybridOpenssl: Option[String] =
    Seq(
      "/opt/homebrew/opt/openssl@3/bin/openssl",
      "/usr/local/opt/openssl@3/bin/openssl",
      "openssl"
    ).find { bin =>
      try Process(Seq(bin, "list", "-tls-groups")).!!.contains(PqTls.Group)
      catch case _: Throwable => false
    }

  private def sClient(
      openssl: String,
      server: TlsRoundServer,
      groups: String,
      extra: String*
  ): (Int, String) =
    collect(
      Seq(
        openssl,
        "s_client",
        "-connect",
        s"localhost:${server.port}",
        "-groups",
        groups,
        "-tls1_3"
      ) ++ extra
    )

  test("a third-party TLS stack (OpenSSL) completes the hybrid handshake"):
    val openssl = hybridOpenssl.getOrElse(
      cancel(s"no openssl here advertises ${PqTls.Group} (needs OpenSSL >= 3.5)")
    )
    withServer { server =>
      val (_, text) = sClient(openssl, server, PqTls.Group, "-alpn", "h2")
      withClue(s"openssl s_client output:\n$text\n"):
        // Assert the NEGOTIATED group, not a bare substring: openssl also echoes the groups the
        // client offered, so `contains("X25519MLKEM768")` would pass even on a downgrade.
        assert(text.contains(s"Negotiated TLS1.3 group: ${PqTls.Group}"))
        assert(text.contains("ALPN protocol: h2"))
    }

  test(s"an OpenSSL client without ${PqTls.Group} is refused"):
    val openssl = hybridOpenssl.getOrElse(cancel("no suitable openssl"))
    withServer { server =>
      val (code, text) = sClient(openssl, server, "x25519")
      assertKeyAgreementRefusal(code, text)
    }
