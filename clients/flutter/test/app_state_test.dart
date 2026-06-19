import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:metadata_messenger/engine/protocol_engine.dart';
import 'package:metadata_messenger/state/app_state.dart';

/// A controllable engine: lets tests push synthetic events and inspect the
/// commands AppState issued. Performs no protocol logic.
class FakeEngine implements ProtocolEngine {
  final _controller = StreamController<EngineEvent>.broadcast();
  final commands = <String>[];
  PrivacyStatus status = const PrivacyStatus(
    backend: 'dev',
    metadataPrivate: false,
    label: devNoPrivacyLabel,
  );

  void emit(EngineEvent e) => _controller.add(e);

  @override
  String get apiVersion => engineApiVersion;
  @override
  PrivacyStatus get privacyStatus => status;
  @override
  Stream<EngineEvent> get events => _controller.stream;

  @override
  Future<AddBuddyResult> addBuddy({
    required String sharedSecret,
    required BuddyRole role,
  }) async {
    commands.add('addBuddy');
    return const AddBuddyResult(pairId: 'p', safetyNumber: '00000');
  }

  @override
  Future<void> confirmBuddy({
    required String pairId,
    required bool matched,
  }) async =>
      commands.add('confirmBuddy:$pairId:$matched');

  @override
  Future<void> removeBuddy({required String pairId}) async =>
      commands.add('removeBuddy:$pairId');

  @override
  Future<void> sendMessage({
    required String pairId,
    required String plaintext,
  }) async =>
      commands.add('sendMessage:$pairId');

  @override
  Future<void> tick({required int roundId}) async =>
      commands.add('tick:$roundId');

  @override
  Future<void> dispose() async => _controller.close();
}

Future<void> _flush() => Future<void>.delayed(Duration.zero);

void main() {
  group('AppState event translation', () {
    test('BuddyConfirmed with no prior optimistic add creates a buddy', () async {
      final engine = FakeEngine();
      final state = AppState(engine);
      engine.emit(const BuddyConfirmed('pair-1', '11111 22222'));
      await _flush();
      expect(state.buddies, hasLength(1));
      expect(state.buddies.single.pairId, 'pair-1');
      expect(state.buddies.single.confirmed, isTrue);
      expect(state.buddies.single.safetyNumber, '11111 22222');
    });

    test('Notified sets the round and acknowledge clears it', () async {
      final engine = FakeEngine();
      final state = AppState(engine);
      engine.emit(const Notified(7));
      await _flush();
      expect(state.lastNotifiedRound, 7);
      state.acknowledgeNotified();
      expect(state.lastNotifiedRound, isNull);
    });

    test('EngineError is surfaced and clearable', () async {
      final engine = FakeEngine();
      final state = AppState(engine);
      engine.emit(const EngineError('boom', 'generic failure'));
      await _flush();
      expect(state.lastError, 'boom: generic failure');
      state.clearError();
      expect(state.lastError, isNull);
    });

    test('MessageReceived is appended to the right conversation', () async {
      final engine = FakeEngine();
      final state = AppState(engine);
      engine.emit(MessageReceived('pair-1', 'hi', DateTime(2026)));
      await _flush();
      final msgs = state.messagesFor('pair-1');
      expect(msgs, hasLength(1));
      expect(msgs.single.plaintext, 'hi');
      expect(msgs.single.mine, isFalse);
      expect(state.messagesFor('other'), isEmpty);
    });

    test('confirmPairing(matched:false) establishes no buddy', () async {
      final engine = FakeEngine();
      final state = AppState(engine);
      await state.confirmPairing(
        pairId: 'p',
        displayName: 'Bob',
        safetyNumber: '0',
        matched: false,
      );
      expect(state.buddies, isEmpty);
      expect(engine.commands, contains('confirmBuddy:p:false'));
    });

    test('confirmPairing(matched:true) adds pending buddy then BuddyConfirmed confirms it',
        () async {
      final engine = FakeEngine();
      final state = AppState(engine);
      await state.confirmPairing(
        pairId: 'p',
        displayName: 'Bob',
        safetyNumber: '0',
        matched: true,
      );
      expect(state.buddies.single.confirmed, isFalse); // optimistic, pending
      engine.emit(const BuddyConfirmed('p', '0'));
      await _flush();
      expect(state.buddies, hasLength(1)); // not duplicated
      expect(state.buddies.single.confirmed, isTrue);
    });

    test('send records the outgoing message as mine and issues the command',
        () async {
      final engine = FakeEngine();
      final state = AppState(engine);
      await state.send('pair-1', '  hello  ');
      expect(state.messagesFor('pair-1').single.mine, isTrue);
      expect(state.messagesFor('pair-1').single.plaintext, 'hello'); // trimmed
      expect(engine.commands, contains('sendMessage:pair-1'));
    });

    test('empty send is a no-op', () async {
      final engine = FakeEngine();
      final state = AppState(engine);
      await state.send('pair-1', '   ');
      expect(state.messagesFor('pair-1'), isEmpty);
      expect(engine.commands, isEmpty);
    });
  });
}
