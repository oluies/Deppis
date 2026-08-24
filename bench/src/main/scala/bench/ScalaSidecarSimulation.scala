package bench

import io.gatling.core.Predef.*
import io.gatling.http.Predef.*
import scala.concurrent.duration.*

/** Load test of the Scala `sidecar-scala` server — the SAME binary sources whether it was linked
  * for the JVM or by Scala Native, so pointing this simulation at each in turn isolates the
  * runtime with everything else held constant.
  *
  * ==Why this is an HTTP simulation and not a gRPC one==
  *
  * The Scala server serves gRPC through `http4s-grpc` on http4s Ember. `fs2-grpc` was not an
  * option: it wraps grpc-java and is therefore JVM-only, while http4s-grpc is pure Scala and does
  * cross-publish for Native. But Ember speaks HTTP/1.1 — measured on both the 0.23 and 1.0.0-M
  * lines, it rejects the HTTP/2 connection preface outright — and grpc-java is HTTP/2 ONLY. So
  * Gatling's gRPC module, which is built on grpc-netty, cannot connect to this server at all.
  *
  * gRPC's framing does not require HTTP/2, though, so this drives the same methods over HTTP/1.1
  * by hand: POST to `/<fully.qualified.Service>/<Method>`, `content-type: application/grpc+proto`,
  * body = 5-byte length prefix ‖ protobuf. The server answers with the same content type and a
  * `grpc-status` trailer, which is exactly what it gives a real gRPC client.
  *
  * ==Read the caveat before comparing these numbers to obsd's==
  *
  * Against `obsd` the transport is HTTP/2 with a grpc-java client; here it is HTTP/1.1 with
  * Gatling's HTTP client. That difference is NOT controlled for, so the honest comparison this
  * pair supports is JVM-vs-Native (identical transport, identical code, one variable), while
  * Rust-vs-Scala across the two simulations carries a transport confound that has to be stated
  * whenever the numbers are quoted. `bench/README.md` says so again, at more length.
  */
class ScalaSidecarSimulation extends Simulation:

  private val host = sys.env.getOrElse("BENCH_HOST", "127.0.0.1")
  private val port = sys.env.getOrElse("BENCH_HTTP_PORT", "50061").toInt
  private val users = sys.env.getOrElse("BENCH_USERS", "50").toInt
  private val duration = sys.env.getOrElse("BENCH_DURATION_S", "30").toInt.seconds
  private val batch = sys.env.getOrElse("BENCH_BATCH", "1").toInt

  private val Service = "metadatamessenger.store.v1.ObliviousStore"

  private val protocol = http
    .baseUrl(s"http://$host:$port")
    .header("content-type", "application/grpc+proto")
    .header("te", "trailers")
    .header("grpc-accept-encoding", "identity")

  private def tokensFor(session: Session): Seq[Array[Byte]] =
    val it = session("iteration").asOption[Int].getOrElse(0)
    (0 until batch).map(i => Workload.token(session.userId.hashCode.toLong * batch + i, it.toLong))

  // A non-empty response body is the liveness check that matters here. http4s-grpc answers a
  // FAILED call with HTTP 200 and an empty body, putting the error in the `grpc-status` trailer —
  // which Gatling's HTTP client does not surface — so checking only the status code would let a
  // server that rejects every request report a perfect run. Both responses carry a non-zero
  // `round_id`, so a successful body is always longer than the 5-byte frame header.
  private val answered = bodyBytes.transform(_.length > 5).is(true)

  private val scn = scenario("sidecar-scala store round (gRPC/HTTP1.1, Scala)")
    .exec(_.set("iteration", 0))
    .during(duration) {
      exec { session => session.set("tokens", tokensFor(session)) }
        .exec(
          http("WriteBatch")
            .post(s"/$Service/WriteBatch")
            .body(ByteArrayBody { session =>
              Workload.grpcFrame(
                Workload.writeRequest(1L, session("tokens").as[Seq[Array[Byte]]]).toByteArray
              )
            })
            .check(status.is(200), answered)
        )
        .exec(
          http("ReadBatch")
            .post(s"/$Service/ReadBatch")
            .body(ByteArrayBody { session =>
              Workload.grpcFrame(
                Workload.readRequest(1L, session("tokens").as[Seq[Array[Byte]]]).toByteArray
              )
            })
            .check(status.is(200), answered)
        )
        .exec(session => session.set("iteration", session("iteration").as[Int] + 1))
    }

  setUp(scn.inject(atOnceUsers(users))).protocols(protocol)
