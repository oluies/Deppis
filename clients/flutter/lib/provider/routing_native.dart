import 'dart:async';
import 'dart:convert';

import 'package:fixnum/fixnum.dart';

import '../generated/provider.pb.dart';
import 'provider_client.dart';
import 'provider_routing.dart';
import 'routing_tuning.dart';

/// Provider routing for the NATIVE engine (iOS/Android), whose Scala.js bundle runs inside an
/// embedded JS runtime (`flutter_js`) rather than a browser — the counterpart of `routing_web.dart`.
///
/// The bundle's `ProviderSession` calls Promise-returning provider methods, and an embedded runtime
/// cannot await Dart. So the two sides exchange messages through `assets/provider-bridge.js`: the
/// session's provider calls arrive here as `{t: 'call'}` messages and are answered through
/// [ProviderClient] (HTTP/2 gRPC natively); the session's own methods are started by evaluating
/// code and settle as `{t: 'done'}` messages. Dart only moves opaque bytes (base64 in transit) and
/// schedules the session; all protocol logic stays in `protocol-core`.

/// The channel `provider-bridge.js` sends on (a flutter_js `sendMessage` channel name).
const providerBridgeChannel = 'deppisProvider';

/// What the bridge needs from the embedded runtime: evaluate code for its effects. Results never
/// come back from an evaluation — they arrive as messages the host passes to
/// [NativeRoutedSession.onMessage] — so a host may run [run] asynchronously.
abstract interface class JsHost {
  /// Evaluate [code]. Returns false when the host already knows the evaluation faulted (then no
  /// message will ever answer it); a host that evaluates asynchronously returns true.
  bool run(String code);
}

/// The `ProviderSession` living in the runtime, driven from Dart. Construct it with [create] after
/// the bundle and `provider-bridge.js` are loaded and the host forwards [providerBridgeChannel]
/// messages to [onMessage].
class NativeRoutedSession implements RoutedSession {
  NativeRoutedSession._(this._host, this._client);

  /// Build a PROVIDER-ROUTED engine (`globalThis.__engine`) and its session for [user] with the
  /// notify [label], in the runtime behind [host]. [tuning] is for test harnesses only; without
  /// it the session uses the network-wide defaults defined in `protocol-core`.
  factory NativeRoutedSession.create(
    JsHost host,
    ProviderClient client, {
    required String user,
    required List<int> label,
    RoutingTuning? tuning,
  }) {
    final s = NativeRoutedSession._(host, client);
    final t = tuning == null
        ? null
        : [
            tuning.refreshEveryRounds,
            tuning.horizonRounds,
            tuning.epochMillis,
            tuning.intervalMillis,
            tuning.cutoffMillis,
            tuning.openGraceMillis,
            tuning.closeGraceMillis,
            tuning.submitMarginMillis,
          ];
    host.run(
      '__routedNew(${jsonEncode(user)}, ${jsonEncode(base64Encode(label))}, ${jsonEncode(t)});',
    );
    return s;
  }

  final JsHost _host;
  final ProviderClient _client;
  final _done = <int, Completer<Object?>>{};
  var _next = 0;

  @override
  Future<void> startAt(int nowMillis) => _run('startAt', nowMillis);

  @override
  Future<void> step(int nowMillis) => _run('step', nowMillis);

  @override
  Future<int> collectAway() async =>
      ((await _run('collectAway', null)) as num?)?.toInt() ?? 0;

  Future<Object?> _run(String method, int? arg) {
    final id = ++_next;
    final c = Completer<Object?>();
    _done[id] = c;
    // A faulted evaluation never sends 'done': fail the call now, or routing would stall for good
    // (steps never overlap, so one call that never settles stops every later step).
    if (!_host.run('__sessionRun($id, ${jsonEncode(method)}, ${jsonEncode(arg)});')) {
      _done.remove(id);
      c.completeError(StateError('provider session call could not start'));
    }
    return c.future;
  }

  /// A message from `provider-bridge.js` (a JSON string, or already decoded by the host). Never
  /// throws: a malformed message is dropped. The work is deferred to a microtask, so a host that
  /// delivers messages synchronously from inside an evaluation is never re-entered.
  void onMessage(Object? message) {
    final Map<String, dynamic> m;
    try {
      final decoded = message is String ? jsonDecode(message) : message;
      m = (decoded as Map).cast<String, dynamic>();
    } catch (_) {
      return;
    }
    scheduleMicrotask(() {
      switch (m['t']) {
        case 'done':
          final c = _done.remove((m['id'] as num).toInt());
          if (c == null) return;
          if (m['ok'] == true) {
            c.complete(m['value']);
          } else {
            c.completeError(StateError('provider session call failed'));
          }
        case 'call':
          _answer((m['id'] as num).toInt(), m['method'] as String?, m['args']);
      }
    });
  }

  Future<void> _answer(int id, String? method, Object? args) async {
    Object? result;
    try {
      result = await _call(method, (args as List).cast<Object?>());
    } catch (_) {
      result = _fallback(method); // a malformed request gets the safe answer, like a failed RPC
    }
    _host.run('__providerReply($id, ${jsonEncode(result)});');
  }

  /// One provider RPC in the bridge's JSON shapes. [ProviderClient] already turns a failed RPC
  /// into the safe answer, so only a malformed request can throw here.
  Future<Object?> _call(String? method, List<Object?> a) async {
    String user() => a[0] as String;
    Int64 round(Object? v) => Int64((v as num).toInt());
    switch (method) {
      case 'register':
        return _client.register(user(), base64Decode(a[1] as String));
      case 'uploadBundle':
        return _client.uploadBundle(
          user(),
          round(a[1]),
          [for (final o in a[2] as List) _ops(o as Map)],
        );
      case 'getDigest':
        final d = await _client.getDigest(user(), round(a[1]));
        return d == null ? null : base64Encode(d);
      case 'submitLive':
        return _client.submitLive(user(), _ops(a[1] as Map));
      case 'collectReceipt':
        final r = await _client.collectReceipt(user(), round(a[1]));
        return r == null
            ? null
            : {
                'roundId': r.roundId.toInt(),
                'ranLive': r.ranLive,
                'writeAccepted': r.writeAccepted,
                'retrieved': r.retrievedPresent ? base64Encode(r.retrieved) : null,
              };
      case 'collectAll':
        return _client.collectAll(user());
      default:
        return null;
    }
  }

  static Object? _fallback(String? method) => switch (method) {
    'register' || 'uploadBundle' || 'submitLive' => false,
    'collectAll' => 0,
    _ => null,
  };
}

Signal _signal(Map s) =>
    Signal(label: base64Decode(s['label'] as String), bit: (s['bit'] as num).toInt());

RoundOps _ops(Map o) => RoundOps(
  roundId: Int64((o['roundId'] as num).toInt()),
  writeToken: base64Decode(o['writeToken'] as String),
  frame: base64Decode(o['frame'] as String),
  signal: _signal(o['signal'] as Map),
  fallbackSignal: _signal(o['fallbackSignal'] as Map),
  readToken: base64Decode(o['readToken'] as String),
);
