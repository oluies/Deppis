package engine

import scala.scalajs.js
import scala.scalajs.js.annotation.{JSExport, JSExportTopLevel}
import scala.scalajs.js.typedarray.Uint8Array

/** Scala.js entry point for the Flutter client (T019, engine-api.md). Dart constructs one instance
  * per session and drives it entirely through the JSON boundary — the same `apiVersion`-gated wire
  * contract validated on the JVM. The engine holds all protocol/crypto state; key material never
  * crosses this boundary.
  *
  * Construct with NO arguments for a local-only engine (no delivery — the dev/bundle default), or
  * with a host-supplied [[JsTransport]] + this client's notify label to drive a real backend
  * (T032b): then `tick` does notify-before-retrieval and surfaces `notified`/`messageReceived`.
  *
  * {{{
  *   const engine = new ProtocolEngine();                  // local only
  *   const engine = new ProtocolEngine(transport, label);  // with a gRPC-web backend
  *   const resp = engine.handle('{"apiVersion":"1","command":"addBuddy","args":{...}}');
  * }}} */
@JSExportTopLevel("ProtocolEngine")
final class EngineJs(
    transport: js.UndefOr[JsTransport] = js.undefined,
    clientLabel: js.UndefOr[Uint8Array] = js.undefined
):
  private val engine: Engine =
    transport.toOption match
      case Some(t) =>
        val label = clientLabel.toOption.map(Uint8.toBytes).getOrElse(Array.emptyByteArray)
        new Engine(Some(new JsRoundTransport(t)), label)
      case None => new Engine()

  private val codec = new EngineCodec(engine)

  /** The engine API version this bundle speaks (Dart sends it on every call). */
  @JSExport val apiVersion: String = EngineApi.Version

  /** Handle one JSON command envelope; returns the JSON response (result+events, or error). */
  @JSExport
  def handle(input: String): String = codec.handle(input)
