// Pinned dependency versions (Constitution XI), in the metabuild so they are reliably in scope for
// build.sbt under the sbt 2.0 Scala 3 metabuild (a `build.sbt`-local object scopes inconsistently).
object V {
  val scalatest = "3.3.0-alpha.2"
  val scalatestPlus = "3.3.0.0-alpha.2"
  val upickle = "4.4.3"
  // ScalaPB runtime + the grpc-java version it targets. Formerly read from
  // `scalapb.compiler.Version`, but ScalaPB's compilerplugin is no longer on the sbt 2.0 metabuild
  // classpath (codegen runs sandboxed — see project/plugins.sbt), so these are pinned here directly.
  val scalapb = "0.11.20"
  val grpcJava = "1.83.1"
  // The audited Signal double-ratchet (Rust core + JNI bindings). Constitution I: we wrap this and
  // never reimplement the ratchet, so keeping it current is a security concern, not just hygiene.
  val libsignal = "0.86.5"
  // Pekko typed actors — the round-orchestration skeleton for the networked TLS server (T020).
  val pekko = "1.7.0"
  // Bouncy Castle — generates the dev self-signed TLS cert (T020); netty's built-in generator uses
  // sun.security internals removed in modern JDKs. Vetted lib (Constitution I).
  val bouncycastle = "1.85"

  // ---- benchmark stack (bench/ + sidecar-scala) ----
  // Gatling: the load driver. 3.13.5 publishes UNSUFFIXED artifacts that are Scala 2.13-compiled;
  // Scala 3 consumes them directly. `gatling-grpc` is FIRST-PARTY as of this line (built on
  // grpc-netty), so no third-party plugin is involved.
  val gatling = "3.15.1"
  // http4s-grpc: a pure-Scala gRPC implementation on http4s — no grpc-java — which is why it, and
  // not fs2-grpc, is what cross-publishes for Scala Native. 0.3.0 targets http4s 0.23.34 and
  // scalapb-runtime 0.11.20 (= V.scalapb above), so the whole stack lines up on one pin.
  val http4sGrpc = "0.3.0"
  val http4s = "0.23.36"
  val catsEffect = "3.7.1"
  val fs2 = "3.13.0"
  val log4cats = "2.8.0" // the newest that publishes for BOTH jvm and native0.5 (2.7.1 is jvm-only)
  val munit = "1.2.4" // match what munit-cats-effect pulls, or Native evicts on test-interface
  val munitCatsEffect = "2.2.0"
}
