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
  // sun.security internals removed in modern JDKs. Vetted lib (Constitution I). bctls also supplies
  // the RFC 10024 hybrid TLS group (transport/.../PqTls.scala).
  //
  // ONE KEY PER ARTIFACT, deliberately. BouncyCastle versions these four independently — bcprov
  // ships patch releases the others do not (1.85.2), and bctls did the same (1.86.1). A single shared
  // key could only ever take a version ALL FOUR publish, so every artifact-only patch produced an
  // unbuildable Steward PR: bcprov 1.85.2 before, bctls 1.86.1 as #147. Separate keys let each move
  // to what actually exists.
  //
  // The SOURCE OF TRUTH for which combination is supported is BouncyCastle's own BOM,
  // org.bouncycastle:bc-jdk18on-bom. `bcBom` names the BOM version these four claim to match, and
  // CI ENFORCES it (scripts/check-bc-bom.py, in the Hygiene job): any key that disagrees with that
  // BOM's pins fails the build. Currently bc-jdk18on-bom 1.86.1: bcprov/bcpkix/bcutil 1.86, bctls
  // 1.86.1 — a mixed set, and BC's own supported configuration.
  //
  // Steward does not track bcBom (it is not a dependency), so a Steward PR bumping any BC key will go
  // RED on that check. Deliberately: every BC bump then needs a human to find the BOM that sanctions
  // the new set and set bcBom plus all four keys to match, in the same PR. (bctls 1.86.1 fixes the 1.86 multi-release-jar NoSuchMethodError:
  // its versions/9 SSLEngineUtil.create now returns javax.net.ssl.SSLEngine, matching the caller —
  // verified with javap. Upstream: bcgit/bc-java#2448.)
  val bcBom = "1.86.1"
  val bcprov = "1.86"
  val bcpkix = "1.86"
  val bctls = "1.86.1"
  val bcutil = "1.86"

  // ---- benchmark stack (bench/ + sidecar-scala) ----
  // Gatling: the load driver. 3.13.5 publishes UNSUFFIXED artifacts that are Scala 2.13-compiled;
  // Scala 3 consumes them directly. `gatling-grpc` is FIRST-PARTY as of this line (built on
  // grpc-netty), so no third-party plugin is involved.
  val gatling = "3.13.5"
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
