import 'dart:async';

import 'package:flutter/foundation.dart';

import '../engine/protocol_engine.dart';

/// A device's provider session as the app drives it (`design/offline-delegation.md`
/// §3). On web this is the exported Scala.js `ProviderSession` — the same
/// session logic the JVM runs; Dart only schedules it.
abstract interface class RoutedSession {
  /// Register and upload the first standing bundle, from the round after the
  /// one in progress at [nowMillis].
  Future<void> startAt(int nowMillis);

  /// Advance to [nowMillis]: hand in the live set once the round is open,
  /// apply the receipt after the cutoff. A no-op while a step is in flight.
  Future<void> step(int nowMillis);

  /// Back after an absence: drop what the provider kept meanwhile.
  Future<int> collectAway();
}

/// Steps a provider-routed engine's [RoutedSession] on a timer while the app is
/// in the foreground, then surfaces the engine's events.
///
/// Going to the background is just [pause]: the device stops stepping, without
/// telling anyone, and the provider runs its standing bundle — the abrupt
/// disconnect the design is built for. [resume] drops what the provider kept
/// and starts stepping again. Holds no protocol state of its own.
class ProviderRouting {
  ProviderRouting(
    this._engine,
    this._session, {
    this.tick = const Duration(milliseconds: 250),
    int Function()? now,
  }) : _now = now ?? (() => DateTime.now().millisecondsSinceEpoch);

  final ProtocolEngine _engine;
  final RoutedSession _session;

  /// How often the session is stepped. Well under the round's submit window.
  final Duration tick;
  final int Function() _now;

  Timer? _timer;
  bool _started = false;
  bool _inFlight = false;

  /// Whether the session is currently being stepped.
  bool get running => _timer != null;

  /// Register with the provider, upload the first bundle, and start stepping.
  Future<void> start() async {
    if (_started) return;
    await _session.startAt(_now());
    _started = true;
    _timer ??= Timer.periodic(tick, (_) => stepOnce());
  }

  /// The app went to the background (or the tab was hidden): stop stepping.
  void pause() {
    _timer?.cancel();
    _timer = null;
  }

  /// Back in the foreground: drop what the provider kept meanwhile, then step
  /// again. A failed call is harmless — senders are still retransmitting.
  Future<void> resume() async {
    if (!_started || _timer != null) return;
    try {
      await _session.collectAway();
    } catch (_) {}
    _timer ??= Timer.periodic(tick, (_) => stepOnce());
  }

  /// One step: advance the session, then pull the engine's events. Steps never
  /// overlap, and a failure never escapes — the session already treats a failed
  /// provider call as a refusal, and engine errors surface as events.
  @visibleForTesting
  Future<void> stepOnce() async {
    if (_inFlight) return;
    _inFlight = true;
    try {
      await _session.step(_now());
      await _engine.pollEvents();
    } catch (e) {
      // Kept out of the round, but never silent: a swallowed failure here once hid a bug that lost
      // every incoming message. The type only — never a value (Constitution II).
      debugPrint('provider round step failed: ${e.runtimeType}');
    } finally {
      _inFlight = false;
    }
  }

  void dispose() => pause();
}
