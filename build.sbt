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

// ---------------------------------------------------------------------------------------------
// AOT cache (JEP 483, "Ahead-of-Time Class Loading & Linking", JDK 24+).
//
// The CLIs are short-lived: measured on `cli.Pcore schedule-next`, ~235 ms of a ~280 ms run was
// classloading the Scala stdlib + upickle + libsignal. A training run records what gets loaded and
// linked; `AOTMode=create` bakes it into a cache the real run maps in. Measured (JDK 26, arm64):
// ~280 ms -> ~60 ms wall and 70 MB -> 50 MB peak RSS, with byte-identical stdout.
//
// TWO HAZARDS, both handled below and in the generated launcher:
//
//   1. STDOUT POISONING. A missing, stale, or JDK-mismatched cache does NOT fail the run — the JVM
//      prints `[error][aot] ...` lines ON STDOUT, ahead of the program's output, and exits 0. These
//      CLIs emit JSON on stdout (Constitution V) and CI's labeling gate greps it (ci.yml), so that
//      would corrupt the contract silently. `-Xlog:disable` is therefore NOT optional: it is what
//      keeps stdout to the program's own output no matter what state the cache is in.
//
//   2. UNSUPPORTED JDK. A JDK without JEP 483 rejects -XX:AOTMode outright ("Improperly specified
//      VM option") and refuses to start, so the flags are only emitted after probing the JDK, and
//      the launcher only passes -XX:AOTCache when the cache file actually exists.
//
// The cache is keyed to the exact JDK and classpath that produced it, so it is a build artifact
// (target/, never committed) and `stageCli` records it against the SAME staged lib/ it writes the
// launcher for. Moving the staged directory or changing JDK invalidates it — which degrades to the
// plain ~280 ms path rather than breaking, thanks to the two guards above.
lazy val aotSupported = taskKey[Boolean]("True if the JDK running sbt supports JEP 483 AOT caches.")
lazy val aotTrainings =
  settingKey[Seq[(String, Seq[String], String)]]("(mainClass, args, stdin) AOT training runs.")

ThisBuild / aotSupported := {
  val javaBin = (file(sys.props("java.home")) / "bin" / "java").getAbsolutePath
  val quiet = scala.sys.process.ProcessLogger(_ => (), _ => ())
  scala.sys.process.Process(Seq(javaBin, "-XX:AOTMode=auto", "-version")).!(quiet) == 0
}

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
    // Training runs for the AOT cache (see the JEP 483 block above). One cache per entry point:
    // `AOTMode=record` writes one config per run, and these are separate main classes. Each entry
    // is (mainClass, args, stdin) — the stdin is representative input, since the point is to load
    // the classes a real invocation loads, not to assert on the output.
    aotTrainings := Seq(
      ("cli.Pcore", Seq("schedule-next"), "{}"),
      ("cli.Pstatus", Seq("show"), "")
    ),
    // Stage the CLIs as a self-contained directory: lib/ jars, one AOT cache per entry point, and a
    // launcher per entry point. Mirrors `transport/stageServer` (sbt-native-packager has no sbt-2
    // build), but additionally records each cache against the SAME absolute lib/ classpath the
    // launcher will use — recording against the module classpath instead would silently invalidate
    // the cache at runtime and cost the entire speedup while still appearing to work.
    // `Unit`, not `File`: sbt 2.0 will not cache a task whose output type is java.io.File/Path
    // (it wants a VirtualFileRef) — same reason `transport/stageServer` returns Unit.
    TaskKey[Unit]("stageCli") := {
      val log = streams.value.log
      val conv = fileConverter.value
      val out = target.value / "cli"
      val lib = out / "lib"
      IO.delete(out); IO.createDirectory(lib)
      (Runtime / fullClasspathAsJars).value
        .map(ref => conv.toPath(ref.data).toFile)
        .foreach(f => IO.copyFile(f, lib / f.getName))
      // The classpath string baked into both the training runs and the launchers. Absolute, so the
      // recorded cache and the launcher agree; the wildcard keeps it stable as lib/ contents change.
      val cp = s"${lib.getAbsolutePath}/*"
      val javaBin = (file(sys.props("java.home")) / "bin" / "java").getAbsolutePath
      val quiet = scala.sys.process.ProcessLogger(_ => (), _ => ())
      val canAot = aotSupported.value
      if (!canAot)
        log.warn(
          s"stageCli: this JDK (${sys.props("java.version")}) has no JEP 483 AOT support — " +
            "staging without caches; launchers fall back to the plain (slower) start path."
        )
      aotTrainings.value.foreach { case (mainClass, args, stdin) =>
        val base = mainClass.split('.').last.toLowerCase
        val cache = out / s"$base.aot"
        if (canAot) {
          val conf = out / s"$base.aotconf"
          val record = scala.sys.process.Process(
            Seq(
              javaBin,
              "-XX:AOTMode=record",
              s"-XX:AOTConfiguration=${conf.getAbsolutePath}",
              "--enable-native-access=ALL-UNNAMED",
              "-cp",
              cp,
              mainClass
            ) ++ args
          ) #< new java.io.ByteArrayInputStream(stdin.getBytes("UTF-8"))
          val create = scala.sys.process.Process(
            Seq(
              javaBin,
              "-XX:AOTMode=create",
              s"-XX:AOTConfiguration=${conf.getAbsolutePath}",
              s"-XX:AOTCache=${cache.getAbsolutePath}",
              "--enable-native-access=ALL-UNNAMED",
              "-cp",
              cp
            )
          )
          // Fail soft: a training run that cannot execute here (missing liboqs, sandbox) must not
          // break packaging — the launcher just takes the plain path, which is correct, only slower.
          if (record.!(quiet) == 0 && create.!(quiet) == 0)
            log.info(
              s"stageCli: AOT cache for $mainClass -> ${cache.getName} " +
                s"(${cache.length() / (1024 * 1024)} MB)"
            )
          else {
            log.warn(
              s"stageCli: AOT training failed for $mainClass — launcher falls back to plain start."
            )
            IO.delete(cache)
          }
          IO.delete(conf)
        }
        // `-Xlog:disable` is load-bearing, not cosmetic — see hazard (1) in the JEP 483 block. The
        // -f test is hazard (2)'s other half: never name a cache file that is not there.
        val launcher = out / base
        IO.write(
          launcher,
          s"""|#!/usr/bin/env bash
              |set -euo pipefail
              |# Generated by `protocolCore/stageCli` — do not edit; regenerate instead.
              |DIR="$$(cd "$$(dirname "$${BASH_SOURCE[0]}")" && pwd)"
              |CACHE="$$DIR/$base.aot"
              |AOT=()
              |[[ -f "$$CACHE" ]] && AOT=(-XX:AOTCache="$$CACHE")
              |exec java -Xlog:disable "$${AOT[@]}" --enable-native-access=ALL-UNNAMED \\
              |  -cp "$$DIR/lib/*" $mainClass "$$@"
              |""".stripMargin
        )
        launcher.setExecutable(true)
      }
      log.info(s"stageCli: staged ${aotTrainings.value.size} launcher(s) to $out")
    },
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
      "org.signal" % "libsignal-client" % V.libsignal,
      // independent vetted Blake2b impl, used only to cross-validate libsodium in KATs
      "org.bouncycastle" % "bcprov-jdk18on" % V.bouncycastle % Test
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
    // ONE copy of the shared contracts. `store.proto` and `notify.proto` used to exist twice — here
    // and under oblivious-sidecar/proto — and the two store.proto files had already drifted apart in
    // their comments while staying wire-identical. Since `bench` gets its stubs from this project,
    // that made the benchmark's "same workload, one contract" premise quietly untrue: the Rust and
    // Scala servers compile the sidecar's copy, the load driver compiled this one. The duplicates
    // are deleted; attestation.proto and messaging.proto are transport-only and stay put.
    Compile / PB.protoSources := Seq(
      (Compile / sourceDirectory).value / "protobuf",
      file("oblivious-sidecar") / "proto"
    ),
    // Suites here must not run concurrently. `PqTls.enforce` reads and writes the process-wide
    // `jdk.tls.namedGroups` (it has to — netty's SslContextBuilder exposes no per-context named
    // groups), and PqTlsSpec deliberately sets that property to a conflicting value to prove
    // enforce() fails closed. Any TlsRoundServer.bind landing inside that window would throw
    // IllegalStateException and fail a test that has nothing to do with the property. sbt runs
    // suites in parallel by default, so serialize them.
    Test / parallelExecution := false,
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
      // Bouncy Castle — dev self-signed TLS cert generation for TlsRoundServer (T020), and the JSSE
      // provider that supplies the RFC 10024 hybrid key agreement (bctls; see PqTls). The JDK's own
      // JSSE offers NO hybrid group even on JDK 26 — measured, see PqTls's doc comment — so the
      // provider swap is what makes post-quantum TLS possible at all. bcutil is bctls's dependency.
      "org.bouncycastle" % "bcprov-jdk18on" % V.bouncycastle,
      "org.bouncycastle" % "bcpkix-jdk18on" % V.bouncycastle,
      "org.bouncycastle" % "bctls-jdk18on" % V.bouncycastle,
      "org.bouncycastle" % "bcutil-jdk18on" % V.bouncycastle
    ) ++ testDeps
  )

// =================================================================================================
// BENCHMARK: sidecar-scala (JVM + Scala Native) and the Gatling load driver.
//
// NOT A PRODUCT. `sidecar-scala` exists to answer "how does a Scala Native + cats-effect
// implementation of the oblivious store compare with the Rust one under load". It carries NO
// privacy claim and is not a deployment target: its constant-time conditional-assign primitives
// are hand-written integer arithmetic, because neither the JVM nor Scala Native offers anything
// like Rust's `subtle` crate, and nothing stops HotSpot or LLVM from reintroducing a branch. The
// Rust sidecar remains the only implementation the metadata-privacy argument rests on.
//
// It reads the SAME `oblivious-sidecar/proto/*.proto` as the Rust build — one contract, no copy.
//
// gRPC via http4s-grpc, NOT fs2-grpc: fs2-grpc wraps grpc-java and is therefore JVM-only, while
// http4s-grpc is a pure-Scala implementation on http4s and cross-publishes for Native.

// The codegen both targets share: ScalaPB for the MESSAGES (grpc = false — http4s-grpc emits its
// own stubs) plus the http4s-grpc generator for the SERVICES. Both run SANDBOXED, the same way
// and for the same reason as `transport`'s ScalaPB generator (see project/plugins.sbt): these are
// _2.12/_2.13 modules that cannot share a classloader with sbt-protoc's protoc-bridge_3.
//
// WHY the http4s-grpc generator runs OUT OF PROCESS while ScalaPB's runs sandboxed in-process.
//
// `http4s-grpc-generator` publishes for Scala 2.12 ONLY (it is consumed by an sbt 1.x plugin).
// protoc-bridge's `SandboxedJvmGenerator` does not fully isolate `scala-library`: the sandbox
// inherits sbt 2's 2.13 one, so the 2.12-compiled generator dies with
//   NoSuchMethodError: scala.collection.JavaConverters$.asScalaBufferConverter
// (that method exists in 2.12 and was removed in 2.13). Pinning ScalaPB's own generator to _2.12
// to match does NOT help — it just moves the failure onto the ScalaPB target, since the leaked
// 2.13 library is the thing that breaks either 2.12 generator. Verified both ways.
//
// A protoc plugin is only a program that reads a CodeGeneratorRequest on stdin and writes a
// CodeGeneratorResponse on stdout, so running it in its own JVM with its own 2.12 classpath
// sidesteps the leak entirely. `sbt-http4s-grpc` (which would normally do this wiring) has no sbt 2
// build, hence doing it by hand here.
//
// The classpath is resolved by SBT, through a hidden ivy configuration — not by shelling out to
// coursier — so codegen needs nothing on PATH beyond a JDK and stays pinned by V.http4sGrpc.
lazy val Http4sGrpcGen = config("http4sGrpcGen").hide

// A plain function, not a settingKey[File]: sbt 2 rejects `File` as a cached task's output type,
// and a File-typed key in this position trips the same check. Both the writer task and
// `sidecarPbTargets` derive the path from `target` through this.
def http4sGrpcPluginPath(t: File): File = t / "protoc-gen-http4s-grpc"

// Unit, not File: sbt 2 caches task results and rejects `File`/`Path` as an output type. The
// script's location is the SETTING above, so nothing needs this task to return it.
lazy val http4sGrpcPlugin = taskKey[Unit](
  "Writes a launcher script that runs the http4s-grpc protoc plugin in its own JVM (2.12 classpath)."
)

lazy val http4sGrpcPluginSettings = Seq(
  ivyConfigurations += Http4sGrpcGen,
  libraryDependencies +=
    ("org.http4s" % "http4s-grpc-generator_2.12" % V.http4sGrpc % Http4sGrpcGen.name),
  // `Def.uncached`: sbt 2 type-checks a redefined task's output for cacheability, and
  // `PB.generate` returns `Seq[File]`, which it rejects. We are only bolting a dependency onto an
  // existing task, so opting its result out of the cache is exactly right. (The error sbt reports
  // for this points at an unrelated line — it was isolated by deleting this one line.)
  Compile / PB.generate := Def.uncached((Compile / PB.generate).dependsOn(http4sGrpcPlugin).value),
  // `PB.targets` is a SETTING, so it cannot read a task's result — the script's location has to be
  // knowable without running anything, and `PB.generate` is made to depend on the task that
  // actually writes it (below).
  http4sGrpcPlugin := {
    val cp = update.value
      .select(configurationFilter(Http4sGrpcGen.name))
      .map(_.getAbsolutePath)
      .mkString(java.io.File.pathSeparator)
    val script = http4sGrpcPluginPath(target.value)
    val javaBin = sys.props.getOrElse("java.home", "") + "/bin/java"
    // `exec` so protoc signals the JVM directly; stderr is left alone (the generator prints
    // protobuf's sun.misc.Unsafe warnings there, and protoc only reads stdout).
    val body =
      s"""|#!/bin/sh
          |exec "$javaBin" -cp "$cp" org.http4s.grpc.generator.Http4sGrpcCodeGenerator "$$@"
          |""".stripMargin
    IO.write(script, body)
    script.setExecutable(true): Unit
  }
)

lazy val sidecarPbTargets = Def.setting(
  Seq(
    Target(
      SandboxedJvmGenerator.forModule(
        "scala",
        Artifact("com.thesamet.scalapb", "compilerplugin_2.13", V.scalapb),
        "scalapb.ScalaPbCodeGenerator$",
        Nil
      ),
      (Compile / sourceManaged).value / "scalapb",
      Nil // no "grpc" option: http4s-grpc generates the service stubs itself
    ),
    Target(
      protocbridge.gens.plugin("http4s-grpc", http4sGrpcPluginPath(target.value).getAbsolutePath),
      (Compile / sourceManaged).value / "http4s-grpc",
      Nil
    )
  )
)

// One contract for the Rust sidecar AND both Scala targets.
lazy val sidecarProtoSources = Def.setting(Seq(file("oblivious-sidecar") / "proto"))

lazy val sidecarScalaSharedSources = Def.setting(
  Seq(file("sidecar-scala") / "shared" / "src" / "main" / "scala")
)

// The JVM build. Same sources as the Native one — the point of the pair is that the ONLY
// difference measured is the runtime underneath.
lazy val sidecarScala = (project in file("sidecar-scala"))
  .settings(http4sGrpcPluginSettings)
  .settings(
    name := "sidecar-scala",
    scalacOptions ++= Seq("-deprecation", "-feature"), // codegen output trips -Wunused
    Compile / PB.protoSources := sidecarProtoSources.value,
    Compile / PB.targets := sidecarPbTargets.value,
    // shared/ plus jvm/ — the platform half of the bounds-check experiment (see UnsafeScan).
    Compile / unmanagedSourceDirectories := sidecarScalaSharedSources.value :+
      (file("sidecar-scala") / "jvm" / "src" / "main" / "scala"),
    Test / unmanagedSourceDirectories := Seq(
      file("sidecar-scala") / "shared" / "src" / "test" / "scala"
    ),
    libraryDependencies ++= Seq(
      "com.thesamet.scalapb" %% "scalapb-runtime" % V.scalapb % "protobuf",
      "com.thesamet.scalapb" %% "scalapb-runtime" % V.scalapb,
      "org.http4s" %% "http4s-grpc" % V.http4sGrpc,
      "org.http4s" %% "http4s-ember-server" % V.http4s,
      "org.http4s" %% "http4s-ember-client" % V.http4s,
      "org.typelevel" %% "log4cats-noop" % V.log4cats,
      "org.typelevel" %% "cats-effect" % V.catsEffect,
      "org.scalameta" %% "munit" % V.munit % Test,
      "org.typelevel" %% "munit-cats-effect" % V.munitCatsEffect % Test
    ),
    Test / testFrameworks := Seq(new TestFramework("munit.Framework")),
    run / fork := true,
    // Writes the runtime classpath to a file so `bench/run-all.sh` can start the JVM server with a
    // plain `java -cp`, the same way it starts the Rust and Native binaries — rather than holding an
    // sbt session open in the background for the duration of a load test.
    TaskKey[Unit]("writeClasspath") := {
      val conv = fileConverter.value
      val cp = (Runtime / fullClasspathAsJars).value
        .map(e => conv.toPath(e.data).toString)
        .mkString(java.io.File.pathSeparator)
      val out = target.value / "sidecar-scala.classpath"
      IO.write(out, cp)
      streams.value.log.info(s"wrote runtime classpath to $out")
    }
  )

// The Scala Native build: the SAME shared/ sources, linked to a standalone binary. Artifact names
// are spelled out (`_native0.5_3`) because sbt 2.0 no longer supplies `%%%` — the same reason
// protocolCoreJS names its `_sjs1_3` artifacts explicitly.
lazy val sidecarScalaNative = (project in file("sidecar-scala-native"))
  .enablePlugins(ScalaNativePlugin)
  .settings(http4sGrpcPluginSettings)
  .settings(
    name := "sidecar-scala-native",
    scalacOptions ++= Seq("-deprecation", "-feature"),
    // munit's Native build is compiled against test-interface 0.5.10 while the plugin here is
    // 0.5.12. That is a patch bump inside 0.5.x, which early-semver treats as compatible; without
    // saying so, sbt's strict eviction check fails the build outright.
    libraryDependencySchemes +=
      "org.scala-native" % "test-interface_native0.5_3" % VersionScheme.EarlySemVer,
    // Benchmark-grade link settings. The defaults are NOT a fair comparison against release-mode
    // Rust and a JIT-warmed JVM, and both defaults bite hard here:
    //
    //   * debug mode skips the optimiser entirely ("Optimizing (debug mode)" in the link log);
    //   * multithreading is auto-DETECTED, and the detector saw no `java.lang.Thread` use in
    //     initial class loading, so it linked a SINGLE-THREADED binary — "Multithreading support
    //     will be disabled to improve performance". A cats-effect server on one core against a JVM
    //     on all of them is not a runtime comparison, it is a core-count comparison.
    //
    // `releaseFast` rather than `releaseFull`, measured rather than assumed: releaseFull buys ~13%
    // on the scan (3,873 -> 3,417 us/round at capacity 4096) and nothing at all once bounds checks
    // are gone, while taking ~47s to link and OOM-ing the linker outright at sbt's default 1 GB
    // heap. It needed -Xmx10g to complete. Not a trade worth making for a benchmark target.
    nativeConfig ~= { c =>
      c.withMode(scala.scalanative.build.Mode.releaseFast)
        .withMultithreading(true)
        .withGC(
          scala.scalanative.build.GC.commix
        ) // parallel GC; immix is the single-threaded default
    },
    Compile / PB.protoSources := sidecarProtoSources.value,
    Compile / PB.targets := sidecarPbTargets.value,
    // shared/ plus this project's own src/main/scala — the Native half of the bounds-check
    // experiment, which needs `scala.scalanative.*` and therefore cannot live in shared/.
    Compile / unmanagedSourceDirectories := sidecarScalaSharedSources.value :+
      (file("sidecar-scala-native") / "src" / "main" / "scala"),
    Test / unmanagedSourceDirectories := Seq(
      file("sidecar-scala") / "shared" / "src" / "test" / "scala"
    ),
    libraryDependencies ++= Seq(
      // the `protobuf` config artifact only supplies .proto files to protoc, so the JVM one is right
      "com.thesamet.scalapb" %% "scalapb-runtime" % V.scalapb % "protobuf",
      "com.thesamet.scalapb" % s"scalapb-runtime_native0.5_3" % V.scalapb,
      "org.http4s" % "http4s-grpc_native0.5_3" % V.http4sGrpc,
      "org.http4s" % "http4s-ember-server_native0.5_3" % V.http4s,
      "org.http4s" % "http4s-ember-client_native0.5_3" % V.http4s,
      "org.typelevel" % "log4cats-noop_native0.5_3" % V.log4cats,
      "org.typelevel" % "cats-effect_native0.5_3" % V.catsEffect,
      "org.scalameta" % "munit_native0.5_3" % V.munit % Test,
      "org.typelevel" % "munit-cats-effect_native0.5_3" % V.munitCatsEffect % Test
    ),
    Test / testFrameworks := Seq(new TestFramework("munit.Framework"))
  )

// The Gatling load driver. Depends on `transport` for the ScalaPB stubs that carry grpc-java
// MethodDescriptors (the gRPC simulation needs them). `transport` now compiles
// oblivious-sidecar/proto directly, so this really is the same single .proto file the Rust sidecar
// and `sidecar-scala` are built from — it previously inherited a second, separately-maintained copy.
//
// No `gatling-sbt` plugin: it has no sbt 2 build. Gatling is launched through its own
// `io.gatling.app.Gatling` entry point by `bench/Run`, which is all the plugin does anyway.
lazy val bench = (project in file("bench"))
  .dependsOn(transport)
  .settings(
    name := "bench",
    scalacOptions ++= Seq("-deprecation", "-feature"),
    publish / skip := true,
    // Gatling 3.13.5 is Scala 2.13-compiled and pulls `scala-collection-compat_2.13`, while
    // ScalaPB's Scala 3 artifacts (via `transport`) pull `_3`. sbt refuses a classpath carrying
    // both suffixes of one module. They provide the same `scala.collection.compat` shims, so we
    // drop the 2.13 copy and let the _3 one serve both — verified by actually running a simulation,
    // not just by compiling.
    excludeDependencies += ExclusionRule("org.scala-lang.modules", "scala-collection-compat_2.13"),
    run / fork := true,
    // Gatling reaches into java.lang internals to intern strings in its stats writer; on a modern
    // JDK that throws `IllegalAccessException: module java.base does not open java.lang` and the
    // run crashes before a single request is sent.
    run / javaOptions ++= Seq(
      "--add-opens=java.base/java.lang=ALL-UNNAMED",
      "--add-opens=java.base/java.util=ALL-UNNAMED"
    ),
    // Gatling writes reports relative to the working directory; keep them out of the repo root.
    run / baseDirectory := (ThisBuild / baseDirectory).value / "bench",
    libraryDependencies ++= Seq(
      // 3.13.5 artifacts are UNSUFFIXED but Scala 2.13-compiled; Scala 3 consumes them directly.
      "io.gatling" % "gatling-app" % V.gatling,
      "io.gatling" % "gatling-core" % V.gatling,
      "io.gatling" % "gatling-http" % V.gatling,
      "io.gatling" % "gatling-charts" % V.gatling,
      // The chart RENDERER, and it lives under a different group id (`io.gatling.highcharts`).
      // Without it Gatling runs the simulation fine and then dies generating the report with
      // "Couldn't find a ComponentLibrary implementation" — after the load is already over.
      "io.gatling.highcharts" % "gatling-charts-highcharts" % V.gatling,
      // FIRST-PARTY gRPC support (grpc-netty under the hood) — not a third-party plugin.
      "io.gatling" % "gatling-grpc" % V.gatling
    )
  )

lazy val root = (project in file("."))
  .aggregate(
    protocolCore,
    protocolCoreJS,
    crypto,
    anonymity,
    server,
    transport,
    sidecarScala,
    bench
  )
  .settings(name := "metadata-messenger", publish / skip := true)

// CI's JVM job runs `testJvm` (the Scala.js job covers protocolCoreJS under Node, so it is excluded
// here to avoid a duplicate Node run). KEEP THIS LIST IN SYNC with the `root` aggregate above when a
// JVM module is added — co-located here, next to the aggregate, so it is hard to miss.
// The Scala Native half of `ObliviousStoreSuite`. It is NOT in the root aggregate or in `testJvm`
// — a Native link needs clang, which the JVM job's runner is not required to have — so it gets its
// own alias and its own CI job. `testFull`, not `test`: sbt 2's `test` delegates to testQuick
// semantics and can run ZERO tests while exiting 0.
addCommandAlias("testNative", ";sidecarScalaNative/testFull")

addCommandAlias(
  "testJvm",
  ";protocolCore/test ;crypto/test ;anonymity/test ;server/test ;transport/test ;sidecarScala/test"
)
