package engine

import scala.scalajs.js.annotation.{JSExport, JSExportTopLevel}

/** Scala.js entry point for the Flutter client (T019, engine-api.md). Dart constructs one instance
  * per session and drives it entirely through the JSON boundary — the same `apiVersion`-gated wire
  * contract validated on the JVM. The engine holds all protocol/crypto state; key material never
  * crosses this boundary.
  *
  * Exposed as the top-level `ProtocolEngine` symbol in the linked bundle:
  * {{{
  *   const engine = new ProtocolEngine();
  *   const resp = engine.handle('{"apiVersion":"1","command":"addBuddy","args":{...}}');
  * }}} */
@JSExportTopLevel("ProtocolEngine")
final class EngineJs:
  private val codec = new EngineCodec(new Engine())

  /** The engine API version this bundle speaks (Dart sends it on every call). */
  @JSExport val apiVersion: String = EngineApi.Version

  /** Handle one JSON command envelope; returns the JSON response (result+events, or error). */
  @JSExport
  def handle(input: String): String = codec.handle(input)
