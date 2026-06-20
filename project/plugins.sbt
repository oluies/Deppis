// ScalaPB / sbt-protoc: compile the gRPC contracts (specs/.../contracts/*.proto) to Scala.
addSbtPlugin("com.thesamet" % "sbt-protoc" % "1.0.7")
libraryDependencies += "com.thesamet.scalapb" %% "compilerplugin" % "0.11.17"

// Scala.js (T019): cross-compile protocol-core to JS for the Flutter engine bundle (pinned).
addSbtPlugin("org.scala-js" % "sbt-scalajs" % "1.18.2")
