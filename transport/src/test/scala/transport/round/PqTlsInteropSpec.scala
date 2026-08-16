package transport.round

import store.dev.DevObliviousStore
import org.scalatest.BeforeAndAfterAll
import org.scalatest.funsuite.AnyFunSuite
import java.io.ByteArrayInputStream
import java.nio.file.{Files, Path}
import java.util.Comparator
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.*
import scala.sys.process.{Process, ProcessLogger}
import scala.util.{Failure, Success, Using}

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
  *   - **Go's `crypto/tls`** — X25519MLKEM768 enabled by default since Go 1.24. The CI job pins a Go
  *     toolchain and sets `REQUIRE_PQ_INTEROP=1`, so this pair cannot silently stop running.
  *   - **OpenSSL** — RFC 10024 support from 3.5. Today's `ubuntu-latest` still ships 3.0.x, so this
  *     pair cancels there and runs on developer machines with a current OpenSSL.
  *
  * Neither peer is asked to *report* the negotiated group. Both are instead **restricted to a single
  * group**, so a completed handshake can only have used it — which sidesteps the trap that a client
  * echoing its own offered list looks identical to a negotiated one. */
class PqTlsInteropSpec extends AnyFunSuite with BeforeAndAfterAll:

  /** Every peer is a child process reached over a socket, so *every* way this can go wrong ends in a
    * blocked read rather than an error. A stalled handshake is not hypothetical: it is the
    * documented failure mode for oversized PQ ClientHellos ([[PqTls]]), and `s_client` holds the
    * connection open by design. Unbounded, that hangs the sbt run with no output. */
  private val PeerTimeout = 60.seconds

  /** Capability probes run before any test body, so they get a bound too — a `go` wedged on a
    * toolchain download would otherwise hang the run before a single test reported. */
  private val ProbeTimeout = 30.seconds

  /** Compiling is deliberately NOT charged against [[PeerTimeout]]: a cold module cache would turn a
    * slow build into a "timeout" that reads like a protocol failure. */
  private val BuildTimeout = 5.minutes

  /** Where the Go module is written, if it was ever built — tracked so [[afterAll]] can remove it. */
  private var scratch: Option[Path] = None

  /** Run `cmd` under `timeout`. Returns (exit code, merged output, timedOut). StringBuffer, not
    * StringBuilder: the logger callbacks run on process-reader threads. */
  private def runBounded(
      cmd: Seq[String],
      cwd: Option[Path],
      timeout: FiniteDuration
  ): (Int, String, Boolean) =
    val out = new StringBuffer
    val logger = ProcessLogger(l => { out.append(l).append('\n'); () })
    val builder = cwd.fold(Process(cmd))(d => Process(cmd, d.toFile))
    // Guard ONLY the launch. A wider try would also cover the wait loop, and an interrupt there
    // would return "did not run" while the child is still alive and still holding its connection to
    // TlsRoundServer — the orphaned-peer condition PeerTimeout and the compiled binary exist to
    // prevent. Empty stdin so peers that read it (s_client) see EOF and exit after the handshake.
    val started =
      try Some(builder.#<(new ByteArrayInputStream(Array.emptyByteArray)).run(logger))
      catch
        // A missing executable surfaces as exit code -1 in this piped shape rather than an
        // exception (verified), but that is a platform detail not worth depending on. Record the
        // throwable: probe() only looks at the code, while a collect() failure here would otherwise
        // report an empty Output: and throw away the one line that explains it.
        case t: Throwable =>
          out.append(s"LAUNCH_FAILED: $t").append('\n')
          None
    started match
      case None => (Int.MinValue, out.toString, false)
      case Some(p) =>
        try
          val deadline = System.nanoTime() + timeout.toNanos
          while p.isAlive() && System.nanoTime() < deadline do Thread.sleep(50)
          if p.isAlive() then (Int.MinValue, out.toString, true)
          else (p.exitValue(), out.toString, false)
        catch
          case t: InterruptedException =>
            Thread.currentThread().interrupt() // don't swallow the interrupt flag
            throw t
        // Every exit path — normal, timed out, interrupted — leaves no live child behind.
        finally if p.isAlive() then p.destroy()

  /** Bounded run for test bodies: a timeout is a test failure, with whatever the peer managed to say. */
  private def collect(cmd: Seq[String], cwd: Option[Path] = None): (Int, String) =
    val (code, text, timedOut) = runBounded(cmd, cwd, PeerTimeout)
    if timedOut then
      fail(s"peer did not exit within $PeerTimeout: ${cmd.mkString(" ")}\noutput so far:\n$text")
    (code, text)

  /** A capability probe: `Some(output)` only when the tool ran and succeeded inside [[ProbeTimeout]]. */
  private def probe(cmd: Seq[String]): Option[String] =
    val (code, text, timedOut) = runBounded(cmd, None, ProbeTimeout)
    Option.when(code == 0 && !timedOut)(text)

  /** A tool being absent is normally a skip, but CI sets `REQUIRE_PQ_INTEROP=1` so the Go pair
    * cannot quietly stop running — a permanently-cancelled test is indistinguishable from a passing
    * one in the summary line, which is the exact hole this spec exists to close. */
  private def unavailable(reason: String): Nothing =
    if sys.env.get("REQUIRE_PQ_INTEROP").contains("1") then
      fail(s"REQUIRE_PQ_INTEROP=1 but $reason")
    else cancel(reason)

  /** Assert a refusal happened at **key agreement**, not somewhere cheaper.
    *
    * Exit status alone is not enough: a peer exits non-zero for a bad argument, a refused
    * connection, or a crash. Nor is the Go client's own `HANDSHAKE_FAILED` marker sufficient on its
    * own — see `main.go`, where dial and handshake are split precisely so that a TCP failure reports
    * `DIAL_FAILED` instead and cannot masquerade as the property under test. */
  private def assertKeyAgreementRefusal(code: Int, text: String): Unit =
    val t = text.toLowerCase
    assert(code != 0, s"a classical-only client must NOT be able to connect. Output:\n$text")
    assert(!t.contains("dial_failed"), s"never reached a handshake — transport failure:\n$text")
    assert(
      t.contains("handshake failure"),
      s"expected a TLS handshake-failure alert, not some other failure. Output:\n$text"
    )

  private def withServer[A](body: TlsRoundServer => A): A =
    val server = TlsRoundServer.bind(new DevObliviousStore)
    try body(server)
    finally server.stop()

  override def afterAll(): Unit =
    try
      scratch.foreach { dir =>
        // Don't discard the Try: a failed walk or delete would otherwise leave the module directory
        // (and the compiled client binary) behind silently — the exact symptom this removes.
        Using(Files.walk(dir))(
          _.sorted(Comparator.reverseOrder()).forEach(Files.deleteIfExists(_))
        ) match
          case Success(_) => scratch = None
          case Failure(e) => Console.err.println(s"[PqTlsInteropSpec] could not remove $dir: $e")
      }
    finally super.afterAll()

  // -----------------------------------------------------------------------------------------
  // Peer 1: Go crypto/tls — the pair that runs in CI
  // -----------------------------------------------------------------------------------------

  /** A **compiled** Go client, if Go >= 1.24 (when `tls.X25519MLKEM768` landed).
    *
    * Compiled rather than `go run`, for two reasons: `go run` execs the real client as a grandchild
    * and does not forward SIGTERM, so a timeout's `destroy()` would kill the wrapper and orphan the
    * client still holding the connection; and it keeps compilation out of the handshake budget. */
  private lazy val goClientBin: Option[Path] =
    val newEnough = probe(Seq("go", "version")) // "go version go1.26.6 darwin/arm64"
      .exists(v => raw"go1\.(\d+)".r.findFirstMatchIn(v).exists(_.group(1).toInt >= 24))
    Option.when(newEnough) {
      val dir = Files.createTempDirectory("deppis-pq-interop")
      scratch = Some(dir)
      Files.writeString(dir.resolve("go.mod"), "module pqinterop\n\ngo 1.24\n")
      // Restricted to ONE curve, so a successful handshake proves that curve was used. Stdlib only,
      // so the build needs no network access.
      Files.writeString(
        dir.resolve("main.go"),
        """package main
          |
          |import (
          |	"crypto/tls"
          |	"fmt"
          |	"net"
          |	"os"
          |)
          |
          |func main() {
          |	curves := []tls.CurveID{tls.X25519MLKEM768}
          |	if len(os.Args) > 2 && os.Args[2] == "classical" {
          |		curves = []tls.CurveID{tls.X25519}
          |	}
          |	// Dial and handshake are SPLIT on purpose. tls.Dial fuses them and reports a TCP connect
          |	// refusal with the same error path as a key-agreement refusal, which would let a dead or
          |	// unbound server masquerade as the no-fallback property under test.
          |	raw, err := net.Dial("tcp", os.Args[1])
          |	if err != nil {
          |		fmt.Println("DIAL_FAILED:", err)
          |		os.Exit(2)
          |	}
          |	defer raw.Close()
          |	conn := tls.Client(raw, &tls.Config{
          |		InsecureSkipVerify: true, // dev cert is self-signed; this asserts key agreement, not PKI
          |		MinVersion:         tls.VersionTLS13,
          |		MaxVersion:         tls.VersionTLS13,
          |		CurvePreferences:   curves,
          |		NextProtos:         []string{"h2"},
          |	})
          |	if err := conn.Handshake(); err != nil {
          |		fmt.Println("HANDSHAKE_FAILED:", err)
          |		os.Exit(1)
          |	}
          |	fmt.Println("HANDSHAKE_OK alpn=" + conn.ConnectionState().NegotiatedProtocol)
          |}
          |""".stripMargin
      )
      val (code, out, timedOut) =
        runBounded(Seq("go", "build", "-o", "client", "."), Some(dir), BuildTimeout)
      if timedOut || code != 0 then fail(s"go build failed (timedOut=$timedOut):\n$out")
      dir.resolve("client")
    }

  private def goClient(bin: Path, server: TlsRoundServer, classical: Boolean): (Int, String) =
    collect(
      Seq(bin.toAbsolutePath.toString, s"localhost:${server.port}") ++
        Option.when(classical)("classical")
    )

  test("a third-party TLS stack (Go crypto/tls) completes the hybrid handshake"):
    val bin = goClientBin.getOrElse(unavailable("no Go >= 1.24 on this machine"))
    withServer { server =>
      val (code, text) = goClient(bin, server, classical = false)
      withClue(s"go client output:\n$text\n"):
        assert(code == 0)
        assert(text.contains("HANDSHAKE_OK alpn=h2"))
    }

  test(s"a Go client without ${PqTls.Group} is refused — hybrid-only has no fallback"):
    val bin = goClientBin.getOrElse(unavailable("no Go >= 1.24 on this machine"))
    withServer { server =>
      val (code, text) = goClient(bin, server, classical = true)
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
    ).find(bin => probe(Seq(bin, "list", "-tls-groups")).exists(_.contains(PqTls.Group)))

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
    // Not gated by REQUIRE_PQ_INTEROP: ubuntu-latest ships OpenSSL 3.0.x, so this pair is expected
    // to cancel in CI and will start running on its own once the runner image reaches 3.5.
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
