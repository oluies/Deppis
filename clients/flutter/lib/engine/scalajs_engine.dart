import 'dart:async';
import 'dart:convert';

import 'protocol_engine.dart';

/// Thrown when the engine returns an error envelope. Carries only the fixed `code`/`message` the
/// engine produced (never secret-dependent — Constitution II).
class EngineException implements Exception {
  EngineException(this.code, this.message);
  final String code;
  final String message;
  @override
  String toString() => 'EngineException($code)';
}

/// [ProtocolEngine] backed by the real Scala.js `protocol-core` engine (T019/T025).
///
/// It talks to the engine ONLY through the versioned JSON boundary from `engine-api.md` — exactly
/// the contract the JVM + Node tests validate. The engine itself is a `String handle(String)`
/// function injected here:
///   * on web it is the linked bundle's `ProtocolEngine.handle` (see `engine_factory_web.dart`);
///   * in tests a fake handle returns canned engine-api JSON, so this whole adapter is exercised
///     without needing the bundle.
///
/// All protocol/crypto state lives inside the engine; this class holds none and sees no key
/// material (the boundary never returns any).
class ScalaJsEngine implements ProtocolEngine {
  ScalaJsEngine(this._handle) {
    // Pull the initial privacy status so the UI can show the mandatory label immediately.
    final resp = _call('privacyStatus', const {});
    _privacy = _parsePrivacy(resp['result'] as Map<String, dynamic>);
    scheduleMicrotask(() => _emit(PrivacyStatusChanged(_privacy)));
  }

  final String Function(String request) _handle;
  final _controller = StreamController<EngineEvent>.broadcast();
  late final PrivacyStatus _privacy;

  @override
  String get apiVersion => engineApiVersion;

  @override
  PrivacyStatus get privacyStatus => _privacy;

  @override
  Stream<EngineEvent> get events => _controller.stream;

  void _emit(EngineEvent e) {
    if (!_controller.isClosed) _controller.add(e);
  }

  /// Build the envelope, call the engine, drain any events, and return the decoded response.
  /// On an error envelope: emit an [EngineError] and throw [EngineException].
  Map<String, dynamic> _call(String command, Map<String, dynamic> args) {
    final request = jsonEncode({
      'apiVersion': engineApiVersion,
      'command': command,
      'args': args,
    });
    final resp = jsonDecode(_handle(request)) as Map<String, dynamic>;
    if (resp.containsKey('error')) {
      final err = resp['error'] as Map<String, dynamic>;
      final code = err['code'] as String;
      final message = err['message'] as String;
      _emit(EngineError(code, message));
      throw EngineException(code, message);
    }
    for (final ev in (resp['events'] as List? ?? const [])) {
      final translated = _translate(ev as Map<String, dynamic>);
      if (translated != null) _emit(translated);
    }
    return resp;
  }

  @override
  Future<AddBuddyResult> addBuddy({
    required String sharedSecret,
    required BuddyRole role,
  }) async {
    final resp = _call('addBuddy', {'sharedSecret': sharedSecret, 'role': role.name});
    final r = resp['result'] as Map<String, dynamic>;
    return AddBuddyResult(
      pairId: r['pairId'] as String,
      safetyNumber: r['safetyNumber'] as String,
    );
  }

  @override
  Future<void> confirmBuddy({required String pairId, required bool matched}) async {
    _call('confirmBuddy', {'pairId': pairId, 'matched': matched});
  }

  @override
  Future<void> removeBuddy({required String pairId}) async {
    _call('removeBuddy', {'pairId': pairId});
  }

  @override
  Future<void> sendMessage({required String pairId, required String plaintext}) async {
    _call('sendMessage', {'pairId': pairId, 'plaintext': plaintext});
  }

  @override
  Future<void> tick({required int roundId}) async {
    _call('tick', {'roundId': roundId});
  }

  @override
  Future<void> dispose() async {
    await _controller.close();
  }

  PrivacyStatus _parsePrivacy(Map<String, dynamic> j) => PrivacyStatus(
        backend: j['backend'] as String,
        metadataPrivate: j['metadataPrivate'] as bool,
        label: j['label'] as String,
      );

  /// Translate an engine event object into a typed [EngineEvent]. Unknown events are ignored
  /// (forward-compat) rather than throwing.
  EngineEvent? _translate(Map<String, dynamic> ev) {
    switch (ev['event'] as String?) {
      case 'buddyConfirmed':
        return BuddyConfirmed(ev['pairId'] as String, ev['safetyNumber'] as String);
      case 'messageReceived':
        return MessageReceived(
          ev['pairId'] as String,
          ev['plaintext'] as String,
          DateTime.fromMillisecondsSinceEpoch((ev['receivedAt'] as num).toInt()),
        );
      case 'notified':
        return Notified((ev['roundId'] as num).toInt());
      case 'privacyStatus':
        return PrivacyStatusChanged(_parsePrivacy(ev));
      default:
        return null;
    }
  }
}
