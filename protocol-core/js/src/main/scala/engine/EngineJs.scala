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
  * Construct with `undefined` + the label for a PROVIDER-ROUTED engine, and drive it with a
  * [[ProviderSessionJs]] (`new ProviderSession(engine, providerApi, user, label)`).
  *
  * {{{
  *   const engine = new ProtocolEngine();                  // local only
  *   const engine = new ProtocolEngine(transport, label);  // with a gRPC-web backend
  *   const engine = new ProtocolEngine(undefined, label);  // provider-routed (ProviderSession)
  *   const resp = engine.handle('{"apiVersion":"1","command":"addBuddy","args":{...}}');
  * }}} */
@JSExportTopLevel("ProtocolEngine")
final class EngineJs(
    transport: js.UndefOr[JsTransport] = js.undefined,
    clientLabel: js.UndefOr[Uint8Array] = js.undefined
):
  private val engine: Engine =
    val label = clientLabel.toOption.map(Uint8.toBytes).getOrElse(Array.emptyByteArray)
    // With no transport but a label, the engine is PROVIDER-ROUTED (design/offline-delegation.md
    // §3): it has no backend of its own and is driven by a `ProviderSession` instead of `tick`,
    // but it still needs its notify label for the digests the provider fetches for it.
    new Engine(transport.toOption.map(t => new JsRoundTransport(t)), label)

  /** The engine itself, for [[ProviderSessionJs]]; never crosses the JS boundary. */
  private[engine] def underlying: Engine = engine

  private val codec = new EngineCodec(engine)

  /** The engine API version this bundle speaks (Dart sends it on every call). */
  @JSExport val apiVersion: String = EngineApi.Version

  /** Handle one JSON command envelope; returns the JSON response (result+events, or error). */
  @JSExport
  def handle(input: String): String = codec.handle(input)
