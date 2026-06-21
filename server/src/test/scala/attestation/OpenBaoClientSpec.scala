package attestation

import com.sun.net.httpserver.{HttpExchange, HttpServer}
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64
import org.scalatest.funsuite.AnyFunSuite

/** OpenBao key-release client, against an IN-PROCESS mock OpenBao (no running server). Proves the
  * client's KV-v2 parsing, token header, and error mapping. The live OpenBao + Shamir unseal +
  * attestation-gated auth + Transit wrap are ops-gated (see `design/attestation-key-provisioning.md`). */
class OpenBaoClientSpec extends AnyFunSuite:

  private val keyBytes = Array.tabulate(32)(i => (i * 3 + 1).toByte)
  private val keyB64 = Base64.getEncoder.encodeToString(keyBytes)

  /** Start a mock OpenBao that runs `handler`, give its base URL to `body`, then shut it down. */
  private def withMock(handler: HttpExchange => Unit)(body: String => Unit): Unit =
    val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
    server.createContext("/", ex => handler(ex))
    server.start()
    try body(s"http://127.0.0.1:${server.getAddress.getPort}")
    finally server.stop(0)

  private def respond(ex: HttpExchange, status: Int, body: String): Unit =
    val bytes = body.getBytes(UTF_8)
    ex.sendResponseHeaders(status, bytes.length.toLong)
    val os = ex.getResponseBody; os.write(bytes); os.close()

  test(
    "readKey returns the base64-decoded key from a KV-v2 response, sending the token header and /v1/ path"
  ):
    var sawToken = ""
    var sawPath = ""
    withMock { ex =>
      sawToken = Option(ex.getRequestHeaders.getFirst("X-Vault-Token")).getOrElse("")
      sawPath = ex.getRequestURI.getPath
      respond(ex, 200, s"""{"data":{"data":{"key":"$keyB64"},"metadata":{"version":1}}}""")
    } { base =>
      val client = new OpenBaoClient(base, token = "s.testtoken")
      val got = client.readKey("secret/data/messenger/notify-key")
      assert(got.map(_.toVector) == Right(keyBytes.toVector))
      assert(sawToken == "s.testtoken", "the X-Vault-Token header must be sent")
      assert(
        sawPath == "/v1/secret/data/messenger/notify-key",
        "the request path must be /v1/<path>"
      )
    }

  test("a 403 maps to a fixed permission-denied error (no secret-dependent detail)"):
    withMock(ex => respond(ex, 403, """{"errors":["permission denied"]}""")) { base =>
      assert(
        new OpenBaoClient(base, "bad").readKey("secret/data/x") == Left(
          "openbao: permission denied"
        )
      )
    }

  test("a 404 maps to secret-not-found"):
    withMock(ex => respond(ex, 404, """{"errors":[]}""")) { base =>
      assert(
        new OpenBaoClient(base, "t").readKey("secret/data/missing") == Left(
          "openbao: secret not found"
        )
      )
    }

  test("a response missing the key field is rejected, not thrown"):
    withMock(ex => respond(ex, 200, """{"data":{"data":{"other":"x"}}}""")) { base =>
      assert(
        new OpenBaoClient(base, "t").readKey("secret/data/x") == Left("openbao: key field absent")
      )
    }

  test("a non-base64 key value is rejected"):
    withMock(ex => respond(ex, 200, """{"data":{"data":{"key":"not valid base64 !!!"}}}""")) {
      base =>
        assert(
          new OpenBaoClient(base, "t").readKey("secret/data/x") == Left(
            "openbao: key field not valid base64"
          )
        )
    }

  test("malformed JSON is rejected"):
    withMock(ex => respond(ex, 200, "not json{")) { base =>
      assert(
        new OpenBaoClient(base, "t").readKey("secret/data/x") == Left("openbao: malformed response")
      )
    }

  test("a connection failure maps to a fixed request-failed error"):
    // Nothing listening on this port.
    assert(
      new OpenBaoClient("http://127.0.0.1:1", "t").readKey("secret/data/x") == Left(
        "openbao: request failed"
      )
    )
