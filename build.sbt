import protocbridge.{Artifact, SandboxedJvmGenerator, Target}

// Metadata-Private Messenger — JVM build (Phase 1/2 foundational slice).
// protocol-core is the single source of truth (Constitution VII). This build currently
// compiles it for the JVM; the Scala.js cross-build (T019) and the server/sidecar/client
// modules are added in later phases as their toolchains land.

ThisBuild / scalaVersion := "3.3.8" // LTS (3.3.x); the Next line is 3.8.x — stay on LTS
ThisBuild / organization := "io.deppis.messenger"
ThisBuild / version := "0.1.0-SNAPSHOT"

// sbt 2.0 no longer auto-detects the ScalaTest framework from the test classpath, so register it
// explicitly for every module (without this, `test` reports "No tests to run" / Total 0).
ThisBuild / Test / testFrameworks := Seq(TestFramework("org.scalatest.tools.Framework"))

// Pinned dependency versions live in `project/V.scala` (reliably in metabuild scope under sbt 2.0).
lazy val testDeps = Seq(
  "org.scalatest" %% "scalatest" % V.scalatest % Test,
  "org.scalatestplus" %% "scalacheck-1-18" % V.scalatestPlus % Test
)

lazy val commonScalac = Seq("-deprecation", "-feature", "-unchecked", "-Wunused:all")

// protocol-core is the single source of truth (Constitution VII), cross-compiled to JVM + Scala.js
// from ONE set of `shared/` sources. The ONLY platform-specific file is `kdf/Kdf.scala` (JVM = JCA
// HMAC; JS = @noble/hashes HMAC) — both vetted, both synchronous, so the two builds are identical.
lazy val protocolCore = (project in file("protocol-core"))
  // JVM-only edge: the JVM `kem.HybridKem` delegates to the vetted `crypto.HybridKem` (X25519 via
  // JCA + ML-KEM-768 via liboqs), so the hybrid KEM has ONE source of truth. `crypto` depends on
  // nothing internal, so this is a legal DAG edge (no cycle). The Scala.js build (`protocolCoreJS`)
  // must NOT get this edge — `crypto` is JVM-only (FFM/liboqs); the JS side reimplements over noble.
  .dependsOn(crypto)
  .settings(
    name := "protocol-core",
    // shared/ (cross-platform) + jvm/ (the JCA Kdf). Same `shared/` dir feeds the JS build below.
    Compile / unmanagedSourceDirectories := Seq(
      baseDirectory.value / "shared" / "src" / "main" / "scala",
      baseDirectory.value / "jvm" / "src" / "main" / "scala"
    ),
    Test / unmanagedSourceDirectories := Seq(
      baseDirectory.value / "shared" / "src" / "test" / "scala",
      // crosstest/ holds the ONE copy of cross-platform specs (e.g. kem.HybridKemCrossSpec) compiled
      // into BOTH this JVM build and protocolCoreJS below, so the pinned KAT vectors are single-
      // sourced. It carries ONLY platform-agnostic specs (uniform `kem.*` API) — unlike shared/src/
      // test, which we do NOT feed to the JS build (it holds JVM-only specs).
      baseDirectory.value / "crosstest" / "src" / "test" / "scala"
    ),
    scalacOptions ++= Seq("-deprecation", "-feature", "-unchecked", "-Wunused:all"),
    // CLIs read JSON from stdin (Constitution V); fork and connect stdin so `run` forwards it.
    run / fork := true,
    run / connectInput := true,
    // The JVM `kem.HybridKem` reaches liboqs (ML-KEM-768) via the `crypto` edge (restricted FFM
    // downcalls), so `kem.HybridKemSpec` exercises native access. Fork the test JVM with native
    // access enabled — matching every other native-touching module (crypto/server/transport) — so
    // the run stays warning-free now and does not break once the JDK makes native access deny-by-
    // default. `run` already touches liboqs transitively, so grant it there too.
    Test / fork := true,
    Test / javaOptions += "--enable-native-access=ALL-UNNAMED",
    run / javaOptions += "--enable-native-access=ALL-UNNAMED",
    libraryDependencies ++= Seq(
      "com.lihaoyi" %% "upickle" % V.upickle,
      "org.scalatest" %% "scalatest" % V.scalatest % Test,
      "org.scalatestplus" %% "scalacheck-1-18" % V.scalatestPlus % Test
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
    // js/src/test (JS-only specs) + crosstest/src/test (the ONE copy of cross-platform specs shared
    // with the JVM build above — e.g. kem.HybridKemCrossSpec, single-sourcing the pinned KATs).
    Test / unmanagedSourceDirectories := Seq(
      protocolCore.base / "js" / "src" / "test" / "scala",
      protocolCore.base / "crosstest" / "src" / "test" / "scala"
    ),
    libraryDependencies ++= Seq(
      // sbt-scalajs 1.22.0 (sbt 2.0) no longer provides the `%%%` operator for plain JS projects,
      // so we name the Scala.js artifacts explicitly (Scala.js 1.x + Scala 3 ⇒ `_sjs1_3`).
      "com.lihaoyi" % "upickle_sjs1_3" % V.upickle,
      "org.scalatest" % "scalatest_sjs1_3" % V.scalatest % Test
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
      "com.lihaoyi" %% "upickle" % V.upickle,
      // Audited Signal double-ratchet (T012/T012a, Constitution I — no hand-rolled ratchet). The
      // MAINTAINED libsignal (Rust core + Java bindings); we wrap it, never reimplement the ratchet.
      "org.signal" % "libsignal-client" % "0.61.0",
      // independent vetted Blake2b impl, used only to cross-validate libsodium in KATs
      "org.bouncycastle" % "bcprov-jdk18on" % "1.78.1" % Test
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
    // Stage the gRPC-web backend server as a plain `lib/` of jars for containerization (T032c,
    // deploy/grpc-web/). sbt-native-packager has no sbt-2 build yet, so we stage by hand:
    // `fullClasspathAsJars` packages the project class dirs + all deps as jars, which we copy into
    // target/grpc-web-server/lib/. Run with `java -cp 'lib/*' transport.round.GrpcWebBackendServer`.
    TaskKey[Unit]("stageServer") := {
      val conv = fileConverter.value // sbt 2 virtual files -> real paths
      val refs = (Runtime / fullClasspathAsJars).value.map(_.data)
      val out = target.value / "grpc-web-server" / "lib"
      IO.delete(out); IO.createDirectory(out)
      refs.foreach { ref =>
        val f = conv.toPath(ref).toFile
        IO.copyFile(f, out / f.getName)
      }
      streams.value.log.info(s"staged ${refs.length} jars to $out")
    },
    // Run the ScalaPB generator SANDBOXED: protoc-bridge loads compilerplugin_2.13 (+ its own
    // protoc-bridge_2.13) in an isolated classloader, so it never clashes with sbt-protoc's
    // protoc-bridge_3 (see project/plugins.sbt). `scalapb.gen(grpc = true)` is unavailable here
    // (compilerplugin isn't on the metabuild classpath), so we build the Target directly.
    Compile / PB.targets := Seq(
      Target(
        SandboxedJvmGenerator.forModule(
          "scala",
          Artifact("com.thesamet.scalapb", "compilerplugin_2.13", V.scalapb),
          "scalapb.ScalaPbCodeGenerator$",
          Nil
        ),
        (Compile / sourceManaged).value / "scalapb",
        Seq("grpc")
      )
    ),
    libraryDependencies ++= Seq(
      "com.thesamet.scalapb" %% "scalapb-runtime" % V.scalapb % "protobuf",
      "com.thesamet.scalapb" %% "scalapb-runtime-grpc" % V.scalapb,
      "io.grpc" % "grpc-netty-shaded" % V.grpcJava,
      "io.grpc" % "grpc-inprocess" % V.grpcJava % Test,
      // Pekko typed actors — the round-orchestration skeleton for the networked TLS server (T020).
      "org.apache.pekko" %% "pekko-actor-typed" % V.pekko,
      "org.apache.pekko" %% "pekko-actor-testkit-typed" % V.pekko % Test,
      // Bouncy Castle — dev self-signed TLS cert generation for TlsRoundServer (T020).
      "org.bouncycastle" % "bcprov-jdk18on" % V.bouncycastle,
      "org.bouncycastle" % "bcpkix-jdk18on" % V.bouncycastle
    ) ++ testDeps
  )

lazy val root = (project in file("."))
  .aggregate(protocolCore, protocolCoreJS, crypto, anonymity, server, transport)
  .settings(name := "metadata-messenger", publish / skip := true)

// CI's JVM job runs `testJvm` (the Scala.js job covers protocolCoreJS under Node, so it is excluded
// here to avoid a duplicate Node run). KEEP THIS LIST IN SYNC with the `root` aggregate above when a
// JVM module is added — co-located here, next to the aggregate, so it is hard to miss.
addCommandAlias(
  "testJvm",
  ";protocolCore/test ;crypto/test ;anonymity/test ;server/test ;transport/test"
)
