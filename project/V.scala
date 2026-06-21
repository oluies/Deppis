// Pinned dependency versions (Constitution XI), in the metabuild so they are reliably in scope for
// build.sbt under the sbt 2.0 Scala 3 metabuild (a `build.sbt`-local object scopes inconsistently).
object V {
  val scalatest = "3.3.0-alpha.2"
  val scalatestPlus = "3.3.0.0-alpha.2"
  val upickle = "4.0.2"
  // ScalaPB runtime + the grpc-java version it targets. Formerly read from
  // `scalapb.compiler.Version`, but ScalaPB's compilerplugin is no longer on the sbt 2.0 metabuild
  // classpath (codegen runs sandboxed — see project/plugins.sbt), so these are pinned here directly.
  val scalapb = "0.11.20"
  val grpcJava = "1.62.2"
  // Pekko typed actors — the round-orchestration skeleton for the networked TLS server (T020).
  val pekko = "1.6.0"
  // Bouncy Castle — generates the dev self-signed TLS cert (T020); netty's built-in generator uses
  // sun.security internals removed in modern JDKs. Vetted lib (Constitution I).
  val bouncycastle = "1.78.1"
}
