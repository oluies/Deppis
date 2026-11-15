import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:math';
import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';

import '../engine/engine_setup.dart';
import '../engine/scalajs_engine.dart';
import '../generated/provider.pb.dart';
import 'provider_client.dart';
import 'provider_routing.dart';
import 'routing_tuning.dart';

/// The browser's provider routing (`design/offline-delegation.md` §3,
/// `grpc-web-transport.md`): a PROVIDER-ROUTED Scala.js engine, driven by the
/// bundle's exported `ProviderSession`, whose provider calls go through
/// [ProviderClient] over gRPC-web. Dart only moves opaque bytes between the two
/// and schedules the session; all protocol logic stays in `protocol-core`.

/// `new ProtocolEngine(null, label)`: an engine with no transport of its own.
@JS('ProtocolEngine')
extension type _RoutedEngine._(JSObject _) implements JSObject {
  external _RoutedEngine(JSAny? transport, JSUint8Array clientLabel);
  external String handle(String input);
}

/// The bundle's `@JSExportTopLevel("ProviderSession")`, constructed by [_newSession].
extension type _JsProviderSession._(JSObject _) implements JSObject {
  external JSPromise<JSAny?> startAt(double nowMillis);
  external JSPromise<JSAny?> step(double nowMillis);
  external JSPromise<JSNumber> collectAway();
}

class _JsRoutedSession implements RoutedSession {
  _JsRoutedSession(this._s);
  final _JsProviderSession _s;

  @override
  Future<void> startAt(int nowMillis) =>
      _s.startAt(nowMillis.toDouble()).toDart;
  @override
  Future<void> step(int nowMillis) => _s.step(nowMillis.toDouble()).toDart;
  @override
  Future<int> collectAway() async => (await _s.collectAway().toDart).toDartInt;
}

/// `new ProviderSession(engine, api, user, label[, tuning…])`. The tuning
/// arguments are appended only when given; otherwise the session uses the
/// network-wide defaults defined in `protocol-core`, never a copy of them here.
_JsProviderSession _newSession(
  _RoutedEngine engine,
  JSObject api,
  String user,
  JSUint8Array label,
  RoutingTuning? t,
) {
  final args = <JSAny?>[engine, api, user.toJS, label];
  if (t != null) {
    args.addAll([
      t.refreshEveryRounds.toJS,
      t.horizonRounds.toJS,
      t.epochMillis.toJS,
      t.intervalMillis.toJS,
      t.cutoffMillis.toJS,
      t.openGraceMillis.toJS,
      t.closeGraceMillis.toJS,
      t.submitMarginMillis.toJS,
    ]);
  }
  final ctor = globalContext['ProviderSession'] as JSFunction;
  return _JsProviderSession._(ctor.callAsConstructorVarArgs<JSObject>(args));
}

/// A routed engine + session for [provider] (Envoy's gRPC-web listener), with a
/// fresh notify label and user name for this run (the engine keeps no state
/// across a reload either). [tuning] is for test harnesses only.
EngineSetup routedSetup(
  Uri provider, {
  RoutingTuning? tuning,
  Duration tick = const Duration(milliseconds: 250),
}) {
  final rng = Random.secure();
  final label = Uint8List.fromList(
    List<int>.generate(16, (_) => rng.nextInt(256)),
  );
  final user =
      'web-${List<int>.generate(8, (_) => rng.nextInt(256)).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
  final client = ProviderClient.connect(
    host: provider.host,
    port: provider.hasPort
        ? provider.port
        : (provider.scheme == 'https' ? 443 : 80),
    secure: provider.scheme == 'https',
  );
  final jsEngine = _RoutedEngine(null, label.toJS);
  final engine = ScalaJsEngine((input) => jsEngine.handle(input));
  final session =
      _newSession(jsEngine, providerApi(client), user, label.toJS, tuning);
  return EngineSetup(
    engine,
    routing: ProviderRouting(engine, _JsRoutedSession(session), tick: tick),
    notifyLabel: label,
  );
}

/// [client] as the `JsProviderApi` object the Scala.js session calls: one
/// Promise-returning function per `provider.proto` RPC, with the shapes the
/// session documents (`{ roundId, writeToken, frame, signal: { label, bit },
/// fallbackSignal, readToken }`; receipts `{ roundId, ranLive, writeAccepted,
/// retrieved }`). Failures are already safe answers inside [ProviderClient].
JSObject providerApi(ProviderClient client) {
  final api = JSObject();
  api['register'] =
      ((String user, JSUint8Array label) =>
              client.register(user, label.toDart).then((ok) => ok.toJS).toJS)
          .toJS;
  api['uploadBundle'] =
      ((String user, double fromRound, JSArray<JSObject> slots) => client
              .uploadBundle(
                user,
                Int64(fromRound.toInt()),
                slots.toDart.map(_ops).toList(),
              )
              .then((ok) => ok.toJS)
              .toJS)
          .toJS;
  api['getDigest'] =
      ((String user, double roundId) => client
              .getDigest(user, Int64(roundId.toInt()))
              .then((d) => d?.toJS)
              .toJS)
          .toJS;
  api['submitLive'] =
      ((String user, JSObject ops) =>
              client.submitLive(user, _ops(ops)).then((ok) => ok.toJS).toJS)
          .toJS;
  api['collectReceipt'] =
      ((String user, double roundId) => client
              .collectReceipt(user, Int64(roundId.toInt()))
              .then((r) => r == null ? null : _receipt(r))
              .toJS)
          .toJS;
  api['collectAll'] =
      ((String user) => client.collectAll(user).then((n) => n.toJS).toJS).toJS;
  return api;
}

Uint8List _bytes(JSObject o, String key) => (o[key] as JSUint8Array).toDart;

Signal _signal(JSObject o) =>
    Signal(label: _bytes(o, 'label'), bit: (o['bit'] as JSNumber).toDartInt);

RoundOps _ops(JSObject o) => RoundOps(
  roundId: Int64((o['roundId'] as JSNumber).toDartInt),
  writeToken: _bytes(o, 'writeToken'),
  frame: _bytes(o, 'frame'),
  signal: _signal(o['signal'] as JSObject),
  fallbackSignal: _signal(o['fallbackSignal'] as JSObject),
  readToken: _bytes(o, 'readToken'),
);

JSObject _receipt(Receipt r) {
  final o = JSObject();
  o['roundId'] = r.roundId.toInt().toJS;
  o['ranLive'] = r.ranLive.toJS;
  o['writeAccepted'] = r.writeAccepted.toJS;
  o['retrieved'] = r.retrievedPresent
      ? Uint8List.fromList(r.retrieved).toJS
      : null;
  return o;
}
