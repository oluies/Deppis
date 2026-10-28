// Pinned dependency versions (Constitution XI), in the metabuild so they are reliably in scope for
// build.sbt under the sbt 2.0 Scala 3 metabuild (a `build.sbt`-local object scopes inconsistently).
object V {
  val scalatest = "3.3.0-alpha.2"
  val scalatestPlus = "3.3.0.0-alpha.2"
  val upickle = "4.4.3"
  // ScalaPB runtime, and the grpc-java version `transport` puts on the classpath beside it
  // (grpc-netty-shaded + grpc-inprocess). Both were formerly read from `scalapb.compiler.Version`,
  // but ScalaPB's compilerplugin is no longer on the sbt 2.0 metabuild classpath (codegen runs
  // sandboxed — see project/plugins.sbt), so they are pinned here directly.
  //
  // These two are NO LONGER in step, and that is worth stating rather than implying otherwise.
  // `grpcJava` used to BE ScalaPB's targeted version — #31 pinned 1.62.2, exactly what
  // scalapb-runtime-grpc declares. Scala Steward has since moved it four times on its own
  // (1.83.1 #102, 1.84.0 #150, 1.84.2 #166, 1.84.3 #175), because Steward tracks the `io.grpc`
  // artifacts directly and knows nothing about what ScalaPB declares. So the pin below is ~22
  // minor versions AHEAD of the grpc-java that scalapb-runtime-grpc 0.11.21 was built against
  // (grpc-stub / grpc-protobuf 1.62.2, read from its POM), and the newer one evicts forward on the
  // shared `transport` classpath.
  //
  // That has held — `transport/test` and the cross-process integration job both exercise the
  // combination on every PR — but it holds by TEST, not by construction: scalapb-runtime-grpc
  // could use a grpc-java API that a later 1.x changes or that was @ExperimentalApi, and nothing
  // here would catch it ahead of a runtime failure. Contrast the BouncyCastle keys a few lines
  // down, where `bcBom` + scripts/check-bc-bom.py make the same class of relationship mechanical
  // and go red on a one-sided bump by design. No equivalent gate exists for this pair; if the
  // forward eviction ever stops being safe, the symptom will be a NoSuchMethodError in the gRPC
  // path rather than a red check.
  val scalapb = "0.11.21"
  val grpcJava = "1.85.1"
  // The audited Signal double-ratchet (Rust core + JNI bindings). Constitution I: we wrap this and
  // never reimplement the ratchet, so keeping it current is a security concern, not just hygiene.
  val libsignal = "0.86.5"
  // Pekko typed actors — the round-orchestration skeleton for the networked TLS server (T020).
  val pekko = "1.7.1"
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
  // BOM's pins fails the build. Currently bc-jdk18on-bom 1.86.2: bcprov/bcpkix/bcutil 1.86, bctls
  // 1.86.2 — a mixed set, and BC's own supported configuration.
  //
  // Steward does not track bcBom (it is not a dependency), so a Steward PR bumping any BC key will go
  // RED on that check. Deliberately: every BC bump then needs a human to find the BOM that sanctions
  // the new set and set bcBom plus all four keys to match, in the same PR. #167 is the worked
  // example: Steward proposed bctls 1.86.2 alone, the check rejected it against BOM 1.86.1, and
  // bc-jdk18on-bom 1.86.2 turned out to sanction exactly that set (bctls 1.86.2, the other three
  // unchanged at 1.86), so only bcBom had to move with it.
  //
  // WHY bctls runs ahead of the other three: 1.86's multi-release jar threw NoSuchMethodError
  // because its versions/9 SSLEngineUtil.create disagreed with the caller's expected return type.
  // 1.86.1 fixed that (upstream bcgit/bc-java#2448) and 1.86.2 keeps it — re-checked with javap on
  // the 1.86.2 jar: versions/9 SSLEngineUtil.create returns javax.net.ssl.SSLEngine, matching the
  // base copy. Worth re-running that javap check on any future bctls bump, since the failure is a
  // runtime NoSuchMethodError rather than anything a compile would catch.
  val bcBom = "1.86.2"
  val bcprov = "1.86"
  val bcpkix = "1.86"
  val bctls = "1.86.2"
  val bcutil = "1.86"

  // ---- benchmark stack (bench/ + sidecar-scala) ----
  // Gatling: the load driver. It publishes UNSUFFIXED artifacts that are Scala 2.13-compiled;
  // Scala 3 consumes them directly. `gatling-grpc` is FIRST-PARTY as of this line (built on
  // grpc-netty), so no third-party plugin is involved.
  val gatling = "3.16.0"
  // http4s-grpc: a pure-Scala gRPC implementation on http4s — no grpc-java — which is why it, and
  // not fs2-grpc, is what cross-publishes for Scala Native. 0.4.0 was built against http4s 0.23.37
  // and scalapb-runtime 0.11.20, and BOTH pins here now sit one patch ahead of that — V.http4s at
  // 0.23.38, V.scalapb at 0.11.21. Deliberate, not drift: both lines keep binary compatibility
  // across patches, so the newer pins evict upward cleanly. If either ever needs to move a MINOR
  // version ahead of what http4s-grpc was built against, check it rather than assuming.
  val http4sGrpc = "0.4.0"
  val http4s = "0.23.38"
  val catsEffect = "3.7.1"
  val fs2 = "3.13.0"
  val log4cats = "2.8.0" // the newest that publishes for BOTH jvm and native0.5 (2.7.1 is jvm-only)
  val munit = "1.3.6" // match what munit-cats-effect pulls, or Native evicts on test-interface
  val munitCatsEffect = "2.2.1"
}
