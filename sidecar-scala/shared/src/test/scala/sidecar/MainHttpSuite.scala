package sidecar

import cats.effect.IO
import cats.effect.std.Mutex
import metadatamessenger.store.v1.store as pb
import munit.CatsEffectSuite
import org.http4s.{Headers, HttpVersion, Method, Request, Uri}

/** Pins the one thing about the HTTP layer that a compile cannot check.
  *
  * http4s-grpc stamps its responses `HTTP/2.0` while Ember frames them as HTTP/1.1 chunked, and
  * netty 4.2.18 (Gatling 3.16.0) rejects that contradiction — which presented as every bench
  * request failing against a server that logged a clean startup and held its port open.
  * [[Main.httpApp]] corrects the version; nothing else in CI would notice if that correction were
  * removed, because `bench/Test/compile` only compiles and no load test runs there.
  *
  * Driven in process against the `HttpApp`, so there is no server, port or Gatling involved.
  * Runs on BOTH the JVM and Scala Native, from this one source. */
class MainHttpSuite extends CatsEffectSuite:

  /** A gRPC frame carrying an empty message: one compression byte + four big-endian length bytes,
    * all zero. An empty `ReadBatchRequest` is valid protobuf (every field defaulted), which is
    * enough to reach http4s-grpc's own response construction — the code path that sets the
    * version. */
  private val emptyGrpcFrame = Array[Byte](0, 0, 0, 0, 0)

  private def appUnderTest: IO[org.http4s.HttpApp[IO]] =
    Mutex[IO].map { mutex =>
      Main.httpApp(pb.ObliviousStore.toRoutes(new StoreService[IO](mutex, new ObliviousStore(16))))
    }

  private def post(path: String, body: Array[Byte]): Request[IO] =
    Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString(path),
      headers = Headers(
        "content-type" -> "application/grpc+proto",
        "te" -> "trailers",
        "grpc-accept-encoding" -> "identity"
      )
    ).withBodyStream(fs2.Stream.emits(body).covary[IO])

  test("a gRPC response is HTTP/1.1, not the HTTP/2.0 http4s-grpc stamps on it") {
    for
      app <- appUnderTest
      resp <- app.run(
        post("/metadatamessenger.store.v1.ObliviousStore/ReadBatch", emptyGrpcFrame)
      )
      // Drain the body: the version is set on the response, but leaving the stream unconsumed
      // would let a failure inside it pass unnoticed.
      _ <- resp.body.compile.drain
    yield
      assertEquals(resp.httpVersion, HttpVersion.`HTTP/1.1`)
      assertEquals(
        resp.headers.get(org.typelevel.ci.CIString("content-type")).map(_.head.value),
        Some("application/grpc+proto")
      )
  }

  /** Not a gate on the fix — verified by removing `withHttpVersion` and watching only the test
    * above fail. http4s's own not-found response is already HTTP/1.1, so this passes either way.
    * It is here to catch the wrapper MANGLING the non-gRPC path, which is a different mistake. */
  test("wrapping the app leaves the not-found path a well-formed HTTP/1.1 response") {
    for
      app <- appUnderTest
      resp <- app.run(post("/no.such.Service/NoSuchMethod", emptyGrpcFrame))
      _ <- resp.body.compile.drain
    yield assertEquals(resp.httpVersion, HttpVersion.`HTTP/1.1`)
  }
