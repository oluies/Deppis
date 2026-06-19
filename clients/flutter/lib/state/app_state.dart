import 'dart:async';

import 'package:flutter/foundation.dart';

import '../engine/protocol_engine.dart';

/// Presentation state: buddies, per-conversation messages, the latest privacy
/// status, and a transient "notified" round marker. Subscribes to the engine's
/// event stream and translates events into UI state (T032 wiring).
///
/// Holds NO key material — only what the engine has already decrypted/derived.
class AppState extends ChangeNotifier {
  AppState(this.engine) {
    _privacy = engine.privacyStatus;
    _sub = engine.events.listen(_onEvent);
  }

  final ProtocolEngine engine;
  late final StreamSubscription<EngineEvent> _sub;

  final List<Buddy> _buddies = [];
  final Map<String, List<Message>> _messages = {};
  PrivacyStatus? _privacy;
  int? _lastNotifiedRound;
  String? _lastError;

  List<Buddy> get buddies => List.unmodifiable(_buddies);
  PrivacyStatus? get privacy => _privacy;
  int? get lastNotifiedRound => _lastNotifiedRound;
  String? get lastError => _lastError;

  List<Message> messagesFor(String pairId) =>
      List.unmodifiable(_messages[pairId] ?? const []);

  void _onEvent(EngineEvent e) {
    switch (e) {
      case PrivacyStatusChanged(:final status):
        _privacy = status;
      case BuddyConfirmed(:final pairId, :final safetyNumber):
        final i = _buddies.indexWhere((b) => b.pairId == pairId);
        if (i >= 0) {
          _buddies[i] =
              _buddies[i].copyWith(confirmed: true, safetyNumber: safetyNumber);
        } else {
          _buddies.add(Buddy(
            pairId: pairId,
            displayName: _nameFor(pairId),
            confirmed: true,
            safetyNumber: safetyNumber,
          ));
        }
      case MessageReceived(:final pairId, :final plaintext, :final receivedAt):
        (_messages[pairId] ??= []).add(Message(
          pairId: pairId,
          plaintext: plaintext,
          mine: false,
          at: receivedAt,
        ));
      case Notified(:final roundId):
        _lastNotifiedRound = roundId;
      case EngineError(:final code, :final message):
        _lastError = '$code: $message';
    }
    notifyListeners();
  }

  /// Confirm a pairing whose safety number the user has compared out of band.
  Future<void> confirmPairing({
    required String pairId,
    required String displayName,
    required String safetyNumber,
    required bool matched,
  }) async {
    if (matched) {
      // Optimistically register the buddy; `buddyConfirmed` will fill details.
      if (!_buddies.any((b) => b.pairId == pairId)) {
        _buddies.add(Buddy(
          pairId: pairId,
          displayName: displayName,
          confirmed: false,
          safetyNumber: safetyNumber,
        ));
        notifyListeners();
      }
    }
    await engine.confirmBuddy(pairId: pairId, matched: matched);
  }

  /// Send a message; record it locally as "mine" immediately.
  Future<void> send(String pairId, String plaintext) async {
    final text = plaintext.trim();
    if (text.isEmpty) return;
    (_messages[pairId] ??= []).add(Message(
      pairId: pairId,
      plaintext: text,
      mine: true,
      at: DateTime.now(),
    ));
    notifyListeners();
    await engine.sendMessage(pairId: pairId, plaintext: text);
  }

  String _nameFor(String pairId) {
    final existing = _buddies.firstWhere(
      (b) => b.pairId == pairId,
      orElse: () => Buddy(pairId: pairId, displayName: pairId, confirmed: false),
    );
    return existing.displayName;
  }

  @override
  void dispose() {
    _sub.cancel();
    super.dispose();
  }
}
