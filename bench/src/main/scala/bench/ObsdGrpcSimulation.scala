package bench

import io.gatling.core.Predef.*
import io.gatling.grpc.Predef.*
import metadatamessenger.store.v1.store.ObliviousStoreGrpc
import scala.concurrent.duration.*

/** Load test of the REAL Rust sidecar (`obsd`) over real gRPC — the production path: tonic,
  * HTTP/2, the `subtle`-based oblivious store.
  *
  * This is the only simulation that measures what actually ships. [[ScalaSidecarSimulation]]
  * measures the Scala comparison, and cannot use this same driver: see that file for why.
  *
  * Start the target first:
  *   cargo build --release --bin obsd --manifest-path oblivious-sidecar/Cargo.toml
  *   OBSD_ADDR=127.0.0.1:50051 OBSD_CAPACITY=4096 ./oblivious-sidecar/target/release/obsd
  */
class ObsdGrpcSimulation extends Simulation:

  private val host = sys.env.getOrElse("BENCH_HOST", "127.0.0.1")
  private val port = sys.env.getOrElse("BENCH_GRPC_PORT", "50051").toInt
  // FIVE, not the 50 the HTTP simulation defaults to, and that is a LICENCE limit rather than a
  // technical one. `io.gatling:gatling-grpc` is first-party but trial-gated:
  //   "GATLING GRPC TRIAL VERSION: gRPC protocol usage is limited, test will shut down when
  //    exceeding 5 virtual users or 5 minutes duration."
  // Exceeding either does not error — Gatling starts the users, shuts the run down, and exits
  // non-zero having recorded NOTHING, which reads exactly like a server that refused every
  // connection. The cap is asserted below so that failure mode can never be mistaken for a result.
  // Lifting it needs Gatling Enterprise, or the Apache-2.0 third-party `com.github.phisgr:
  // gatling-grpc`, which has no such cap.
  private val users = sys.env.getOrElse("BENCH_USERS", "5").toInt
  private val duration = sys.env.getOrElse("BENCH_DURATION_S", "30").toInt.seconds
  require(
    users <= 5,
    s"gatling-grpc's trial licence caps this simulation at 5 virtual users; got $users. " +
      "Run the comparison at 5 users, or switch to an unlimited gRPC module."
  )
  require(
    duration <= 5.minutes,
    s"gatling-grpc's trial licence caps this simulation at 5 minutes; got $duration."
  )
  private val batch = sys.env.getOrElse("BENCH_BATCH", "1").toInt

  // The protocol builder is constructed directly rather than through the `grpc` DSL alias. `grpc`
  // is overloaded — one overload takes the implicit GatlingConfiguration and yields this PROTOCOL
  // builder, the other takes a request name and yields a request builder — and with Gatling's
  // `value2Expression` conversion in scope, Scala 3 resolves even the explicit
  // `grpc(configuration)` form to the request-name overload. Naming the type sidesteps that.
  private val protocol = io.gatling.grpc.protocol
    .GrpcProtocolBuilder(io.gatling.core.Predef.configuration)
    .forAddress(host, port)
    // No parens on these two: they are parameterless Scala defs, and Gatling's `value2Expression`
    // conversion means `usePlaintext()` is read as applying `Function1.apply` to the RESULT —
    // which fails with a baffling "missing argument for parameter v1" instead of an arity error.
    .usePlaintext
    .shareChannel

  private def tokensFor(session: Session): Seq[Array[Byte]] =
    val it = session("iteration").asOption[Int].getOrElse(0)
    (0 until batch).map(i => Workload.token(session.userId.hashCode.toLong * batch + i, it.toLong))

  private val scn = scenario("obsd store round (gRPC/HTTP2, Rust)")
    .exec(_.set("iteration", 0))
    .during(duration) {
      exec { session => session.set("tokens", tokensFor(session)) }
        .exec(
          grpc("WriteBatch")
            .unary(ObliviousStoreGrpc.METHOD_WRITE_BATCH)
            .send { session =>
              Workload.writeRequest(1L, session("tokens").as[Seq[Array[Byte]]])
            }
        )
        .exec(
          grpc("ReadBatch")
            .unary(ObliviousStoreGrpc.METHOD_READ_BATCH)
            .send { session =>
              Workload.readRequest(1L, session("tokens").as[Seq[Array[Byte]]])
            }
        )
        .exec(session => session.set("iteration", session("iteration").as[Int] + 1))
    }

  setUp(scn.inject(atOnceUsers(users))).protocols(protocol)
