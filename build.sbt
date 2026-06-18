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

lazy val protocolCore = (project in file("protocol-core"))
  .settings(
    name := "protocol-core",
    // Sources live under shared/ so the later Scala.js cross-build reuses them verbatim.
    Compile / scalaSource := baseDirectory.value / "shared" / "src" / "main" / "scala",
    Test / scalaSource    := baseDirectory.value / "shared" / "src" / "test" / "scala",
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
  .dependsOn(protocolCore)
  .settings(
    name := "server",
    scalacOptions ++= commonScalac,
    Compile / unmanagedSourceDirectories := Seq("pong", "ping", "provider", "attestation")
      .map(d => baseDirectory.value / d / "src" / "main" / "scala"),
    Test / unmanagedSourceDirectories := Seq("pong", "ping", "provider", "attestation")
      .map(d => baseDirectory.value / d / "src" / "test" / "scala"),
    libraryDependencies ++= testDeps
  )

lazy val root = (project in file("."))
  .aggregate(protocolCore, anonymity, server)
  .settings(name := "metadata-messenger", publish / skip := true)
