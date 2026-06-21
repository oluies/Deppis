// ScalaPB / sbt-protoc: compile the gRPC contracts (specs/.../contracts/*.proto) to Scala.
//
// sbt 2.x note: sbt-protoc's sbt 2 build is 1.1.0-RC1 (the latest `_sbt2_3` artifact) and pulls
// protoc-bridge_3. ScalaPB's `compilerplugin` is still built against protoc-bridge_2.13, so it
// CANNOT share a classloader with sbt-protoc's protoc-bridge_3 (binary-incompatible — the
// `ProtocCodeGenerator` trait init differs between Scala 2.13 and 3). We therefore do NOT add
// compilerplugin to the metabuild; instead build.sbt runs the ScalaPB generator SANDBOXED via
// protoc-bridge's `SandboxedJvmGenerator` (its own isolated classloader resolves compilerplugin_2.13
// + protoc-bridge_2.13), so the two protoc-bridge versions never meet. Revisit when ScalaPB ships a
// protoc-bridge_3 compilerplugin and sbt-protoc GAs for sbt 2.
addSbtPlugin("com.thesamet" % "sbt-protoc" % "1.1.0-RC1")

// Scala.js (T019): cross-compile protocol-core to JS for the Flutter engine bundle (pinned).
addSbtPlugin("org.scala-js" % "sbt-scalajs" % "1.22.0")
