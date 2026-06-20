import scalapb.compiler.Version.{scalapbVersion, grpcJavaVersion}

// Metadata-Private Messenger — JVM build (Phase 1/2 foundational slice).
// protocol-core is the single source of truth (Constitution VII). This build currently
// compiles it for the JVM; the Scala.js cross-build (T019) and the server/sidecar/client
// modules are added in later phases as their toolchains land.

ThisBuild / scalaVersion := "3.3.4" // LTS
ThisBuild / organization := "io.deppis.messenger"
ThisBuild / version      := "0.1.0-SNAPSHOT"

// Dependency versions pinned (Constitution XI).
lazy val V = new {
  val scalatest      = "3.2.19"
  val scalatestPlus  = "3.2.19.0"
  val upickle        = "4.0.2"
}

lazy val testDeps = Seq(
  "org.scalatest"     %% "scalatest"       % V.scalatest     % Test,
  "org.scalatestplus" %% "scalacheck-1-18" % V.scalatestPlus % Test
)

lazy val commonScalac = Seq("-deprecation", "-feature", "-unchecked", "-Wunused:all")

// protocol-core is the single source of truth (Constitution VII), cross-compiled to JVM + Scala.js
// from ONE set of `shared/` sources. The ONLY platform-specific file is `kdf/Kdf.scala` (JVM = JCA
// HMAC; JS = @noble/hashes HMAC) — both vetted, both synchronous, so the two builds are identical.
lazy val protocolCore = (project in file("protocol-core"))
  .settings(
    name := "protocol-core",
    // shared/ (cross-platform) + jvm/ (the JCA Kdf). Same `shared/` dir feeds the JS build below.
    Compile / unmanagedSourceDirectories := Seq(
      baseDirectory.value / "shared" / "src" / "main" / "scala",
      baseDirectory.value / "jvm" / "src" / "main" / "scala"
    ),
    Test / unmanagedSourceDirectories := Seq(baseDirectory.value / "shared" / "src" / "test" / "scala"),
    scalacOptions ++= Seq("-deprecation", "-feature", "-unchecked", "-Wunused:all"),
    // CLIs read JSON from stdin (Constitution V); fork and connect stdin so `run` forwards it.
    run / fork         := true,
    run / connectInput := true,
    libraryDependencies ++= Seq(
      "com.lihaoyi"       %% "upickle"          % V.upickle,
      "org.scalatest"     %% "scalatest"        % V.scalatest     % Test,
      "org.scalatestplus" %% "scalacheck-1-18"  % V.scalatestPlus % Test
    )
  )

// The Scala.js build of protocol-core: the SAME shared/ sources + js/ (the @noble/hashes Kdf + the
// @JSExportTopLevel `ProtocolEngine` facade). `fastLinkJS`/`fullLinkJS` emit the bundle Dart loads;
// the engine tests run here under Node (real @noble/hashes HMAC), cross-checked against the JVM JCA.
// @noble/hashes is browser-safe too, so the same bundle loads in Flutter web (with a bundler/import
// map resolving the bare `@noble/...` specifiers).
lazy val protocolCoreJS = (project in file("protocol-core-js"))
  .enablePlugins(ScalaJSPlugin)
  .settings(
    name := "protocol-core-js",
    // CommonJS module so `import crypto` (Node) resolves; tests run under Node.
    scalaJSLinkerConfig ~= (_.withModuleKind(ModuleKind.CommonJSModule)),
    scalacOptions ++= Seq("-deprecation", "-feature", "-unchecked", "-Wunused:all"),
    Compile / unmanagedSourceDirectories := Seq(
      (protocolCore.base / "shared" / "src" / "main" / "scala"),
      (protocolCore.base / "js" / "src" / "main" / "scala")
    ),
    Test / unmanagedSourceDirectories := Seq(protocolCore.base / "js" / "src" / "test" / "scala"),
    libraryDependencies ++= Seq(
      "com.lihaoyi"   %%% "upickle"   % V.upickle,
      "org.scalatest" %%% "scalatest" % V.scalatest % Test
    )
  )

// crypto: thin wrappers over libsodium via the JDK Foreign Function & Memory API (Panama).
// No hand-rolled primitives (Constitution I). Forked with native access enabled.
lazy val crypto = (project in file("crypto"))
  .settings(
    name := "crypto",
    scalacOptions ++= commonScalac,
    run / fork := true,
    Test / fork := true,
    run / javaOptions += "--enable-native-access=ALL-UNNAMED",
    Test / javaOptions += "--enable-native-access=ALL-UNNAMED",
    libraryDependencies ++= testDeps ++ Seq(
      "com.lihaoyi"      %% "upickle"        % V.upickle,
      // Audited Signal double-ratchet (T012/T012a, Constitution I — no hand-rolled ratchet). The
      // MAINTAINED libsignal (Rust core + Java bindings); we wrap it, never reimplement the ratchet.
      "org.signal" % "libsignal-client" % "0.61.0",
      // independent vetted Blake2b impl, used only to cross-validate libsodium in KATs
      "org.bouncycastle"  % "bcprov-jdk18on" % "1.78.1" % Test
    )
  )

// anonymity layer: AnonymityLayer interface (+ Groove stub later). Standard layout.
lazy val anonymity = (project in file("anonymity"))
  .dependsOn(protocolCore)
  .settings(
    name := "anonymity",
    scalacOptions ++= commonScalac,
    libraryDependencies ++= testDeps
  )

// server: PING/PONG/provider/attestation fronts. Sources live in per-role subdirs to match the
// plan structure (server/pong/..., server/ping/..., etc.).
lazy val server = (project in file("server"))
  .dependsOn(protocolCore, crypto)
  .settings(
    name := "server",
    scalacOptions ++= commonScalac,
    // ping aggregation seals tokens via libsodium (crypto, FFM) -> fork tests w/ native access.
    Test / fork := true,
    Test / javaOptions += "--enable-native-access=ALL-UNNAMED",
    // ++= keeps the default server/src/main/scala root (where T018 obs/logging will live)
    // alongside the per-role dirs.
    Compile / unmanagedSourceDirectories ++= Seq("pong", "ping", "provider", "attestation")
      .map(d => baseDirectory.value / d / "src" / "main" / "scala"),
    Test / unmanagedSourceDirectories ++= Seq("pong", "ping", "provider", "attestation")
      .map(d => baseDirectory.value / d / "src" / "test" / "scala"),
    // ujson (OpenBaoClient) — made a direct dependency rather than relying on a transitive pull
    // through protocol-core/crypto, so the server keeps compiling if those drop upickle.
    libraryDependencies ++= testDeps :+ ("com.lihaoyi" %% "upickle" % V.upickle)
  )

// transport: gRPC contracts compiled by ScalaPB + the round service/client over them. Generated
// code lives under sourceManaged; we drop -Wunused here so codegen doesn't produce noise.
lazy val transport = (project in file("transport"))
  .dependsOn(protocolCore, server)
  .settings(
    name := "transport",
    scalacOptions ++= Seq("-deprecation", "-feature"),
    // the notification service front loads libsodium (crypto, FFM) -> fork w/ native access.
    Test / fork := true,
    Test / javaOptions += "--enable-native-access=ALL-UNNAMED",
    // DeppisDemo's PING-front stand-in seals tokens via libsodium too -> same for `runMain`.
    run / fork := true,
    run / javaOptions += "--enable-native-access=ALL-UNNAMED",
    run / connectInput := true,
    Compile / PB.targets := Seq(scalapb.gen(grpc = true) -> (Compile / sourceManaged).value / "scalapb"),
    libraryDependencies ++= Seq(
      "com.thesamet.scalapb" %% "scalapb-runtime"      % scalapbVersion % "protobuf",
      "com.thesamet.scalapb" %% "scalapb-runtime-grpc" % scalapbVersion,
      "io.grpc"               % "grpc-netty-shaded"     % grpcJavaVersion,
      "io.grpc"               % "grpc-inprocess"        % grpcJavaVersion % Test
    ) ++ testDeps
  )

lazy val root = (project in file("."))
  .aggregate(protocolCore, protocolCoreJS, crypto, anonymity, server, transport)
  .settings(name := "metadata-messenger", publish / skip := true)
