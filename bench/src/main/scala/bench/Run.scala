package bench

import io.gatling.app.Gatling
import io.gatling.shared.cli.GatlingCliOptions

/** Launches Gatling without the `gatling-sbt` plugin, which has no sbt 2 build. All the plugin
  * does is call this entry point with the simulation class and a results directory.
  *
  * Usage: `sbt "bench/runMain bench.Run bench.ObsdGrpcSimulation"` */
object Run:
  def main(args: Array[String]): Unit =
    val simulation = args.headOption.getOrElse {
      System.err.println(
        "usage: bench.Run <simulation-class>\n" +
          "  bench.ObsdGrpcSimulation      the Rust sidecar over gRPC/HTTP2\n" +
          "  bench.ScalaSidecarSimulation  the Scala sidecar over gRPC/HTTP1.1"
      )
      sys.exit(2)
    }
    // `target/gatling`, NOT `bench/target/gatling`: build.sbt already sets this project's
    // `run / baseDirectory` to <root>/bench, so the relative path was resolving to
    // bench/bench/target/gatling while the README and the runner pointed at an empty directory.
    Gatling.main(Array("-s", simulation, "-rf", "target/gatling"))
