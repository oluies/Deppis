import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:metadata_messenger/engine/protocol_engine.dart';
import 'package:metadata_messenger/engine/scalajs_engine.dart';

/// A fake engine handle that mimics the Scala.js engine's JSON boundary (engine-api.md), so the
/// entire [ScalaJsEngine] adapter — envelope construction, response parsing, event translation —
/// is exercised in pure Dart without needing the real bundle (which is covered separately by the
/// Node `engine-contract.cjs` e2e). It keeps just enough state to be realistic.
class FakeHandle {
  final _pending = <String, String>{}; // pairId -> safetyNumber
  final _confirmed = <String>{};
  int _seq = 0;

  String call(String request) {
    final req = jsonDecode(request) as Map<String, dynamic>;
    if (req['apiVersion'] != '1') return _error('api_version', 'unsupported apiVersion');
    final args = (req['args'] as Map<String, dynamic>?) ?? const {};
    switch (req['command'] as String) {
      case 'privacyStatus':
        return _ok({
          'event': 'privacyStatus',
          'backend': 'Dev',
          'metadataPrivate': false,
          'label': devNoPrivacyLabel,
        });
      case 'addBuddy':
        final secret = args['sharedSecret'] as String;
        if (secret.isEmpty) return _error('invalid_arg', 'shared secret required');
        final pairId = 'pair-${_seq++}';
        final safety = '11111 22222 33333 44444 55555 66666';
        _pending[pairId] = safety;
        return _ok({'pairId': pairId, 'safetyNumber': safety});
      case 'confirmBuddy':
        final pairId = args['pairId'] as String;
        final matched = args['matched'] as bool;
        final safety = _pending.remove(pairId);
        if (safety == null) return _error('confirm_failed', 'unknown pair');
        if (matched) {
          _confirmed.add(pairId);
          return _ok(null, [
            {'event': 'buddyConfirmed', 'pairId': pairId, 'safetyNumber': safety}
          ]);
        }
        return _ok(null);
      case 'removeBuddy':
        _confirmed.remove(args['pairId']);
        return _ok(null);
      case 'sendMessage':
        if (!_confirmed.contains(args['pairId'])) {
          return _error('unknown_pair', 'no confirmed buddy for that pair');
        }
        return _ok({'queued': 1});
      case 'tick':
        return _ok({'roundId': args['roundId'], 'carrier': true, 'retrieve': true});
      default:
        return _error('unknown_command', 'unsupported command');
    }
  }

  String _ok(Object? result, [List<Map<String, dynamic>> events = const []]) =>
      jsonEncode({'apiVersion': '1', 'result': result, 'events': events});
  String _error(String code, String message) =>
      jsonEncode({'apiVersion': '1', 'error': {'code': code, 'message': message}});
}

Future<void> _flush() => Future<void>.delayed(Duration.zero);

void main() {
  group('ScalaJsEngine over the JSON boundary', () {
    test('reports the dev privacy status from the engine on construction', () async {
      final engine = ScalaJsEngine(FakeHandle().call);
      expect(engine.apiVersion, engineApiVersion);
      expect(engine.privacyStatus.metadataPrivate, isFalse);
      expect(engine.privacyStatus.label, devNoPrivacyLabel);
      final ev = await engine.events.firstWhere((e) => e is PrivacyStatusChanged);
      expect((ev as PrivacyStatusChanged).status.metadataPrivate, isFalse);
    });

    test('addBuddy returns the pairId + safety number from the engine result', () async {
      final engine = ScalaJsEngine(FakeHandle().call);
      final r = await engine.addBuddy(sharedSecret: 'abc', role: BuddyRole.initiator);
      expect(r.pairId, 'pair-0');
      expect(r.safetyNumber.split(' ').length, 6);
    });

    test('an engine error envelope throws EngineException and emits EngineError', () async {
      final engine = ScalaJsEngine(FakeHandle().call);
      final errors = <EngineError>[];
      engine.events.listen((e) {
        if (e is EngineError) errors.add(e);
      });
      await expectLater(
        engine.addBuddy(sharedSecret: '', role: BuddyRole.responder),
        throwsA(isA<EngineException>()),
      );
      await _flush();
      expect(errors.single.code, 'invalid_arg');
    });

    test('confirmBuddy(matched) translates the buddyConfirmed event onto the stream', () async {
      final engine = ScalaJsEngine(FakeHandle().call);
      final r = await engine.addBuddy(sharedSecret: 'abc', role: BuddyRole.initiator);
      final ev = engine.events.firstWhere((e) => e is BuddyConfirmed);
      await engine.confirmBuddy(pairId: r.pairId, matched: true);
      final confirmed = await ev as BuddyConfirmed;
      expect(confirmed.pairId, r.pairId);
      expect(confirmed.safetyNumber, r.safetyNumber);
    });

    test('sendMessage requires a confirmed buddy (engine enforces; adapter surfaces the error)',
        () async {
      final engine = ScalaJsEngine(FakeHandle().call);
      final r = await engine.addBuddy(sharedSecret: 'abc', role: BuddyRole.initiator);
      await expectLater(
        engine.sendMessage(pairId: r.pairId, plaintext: 'hi'),
        throwsA(isA<EngineException>()),
      );
      await engine.confirmBuddy(pairId: r.pairId, matched: true);
      await engine.sendMessage(pairId: r.pairId, plaintext: 'hi'); // now allowed
    });

    test('tick is accepted by the engine boundary', () async {
      final engine = ScalaJsEngine(FakeHandle().call);
      await engine.tick(roundId: 7); // no throw
    });
  });

  group('ScalaJsEngine event translation', () {
    // A handle whose privacyStatus is fixed and whose `tick` returns a caller-supplied events array,
    // so the adapter's _translate of every engine event shape is exercised. (A backend-connected
    // engine is what would actually emit notified/messageReceived — see T032a follow-up.)
    String Function(String) handleEmitting(List<Map<String, dynamic>> events) => (request) {
          final req = jsonDecode(request) as Map<String, dynamic>;
          if (req['command'] == 'privacyStatus') {
            return jsonEncode({
              'apiVersion': '1',
              'result': {'event': 'privacyStatus', 'backend': 'Dev', 'metadataPrivate': false, 'label': devNoPrivacyLabel},
              'events': <Map<String, dynamic>>[],
            });
          }
          return jsonEncode({'apiVersion': '1', 'result': null, 'events': events});
        };

    test('a notified event is translated onto the stream', () async {
      final engine = ScalaJsEngine(handleEmitting([
        {'event': 'notified', 'roundId': 5}
      ]));
      final ev = engine.events.firstWhere((e) => e is Notified);
      await engine.tick(roundId: 5);
      expect((await ev as Notified).roundId, 5);
    });

    test('a messageReceived event is translated onto the stream', () async {
      final at = DateTime(2026, 6, 20).millisecondsSinceEpoch;
      final engine = ScalaJsEngine(handleEmitting([
        {'event': 'messageReceived', 'pairId': 'p1', 'plaintext': 'hi', 'receivedAt': at}
      ]));
      final ev = engine.events.firstWhere((e) => e is MessageReceived);
      await engine.tick(roundId: 1);
      final m = await ev as MessageReceived;
      expect(m.pairId, 'p1');
      expect(m.plaintext, 'hi');
      expect(m.receivedAt.millisecondsSinceEpoch, at);
    });

    test('a privacyStatus event is translated onto the stream', () async {
      final engine = ScalaJsEngine(handleEmitting([
        {'event': 'privacyStatus', 'backend': 'EnclaveTarget', 'metadataPrivate': true, 'label': 'METADATA PRIVATE'}
      ]));
      final ev = engine.events.firstWhere(
        (e) => e is PrivacyStatusChanged && e.status.metadataPrivate,
      );
      await engine.tick(roundId: 1);
      expect((await ev as PrivacyStatusChanged).status.backend, 'EnclaveTarget');
    });

    test('an unknown event shape is ignored, not thrown', () async {
      final engine = ScalaJsEngine(handleEmitting([
        {'event': 'somethingNew', 'x': 1}
      ]));
      await engine.tick(roundId: 1); // no throw; unknown events are dropped
    });
  });
}
