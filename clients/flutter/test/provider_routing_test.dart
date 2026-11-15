import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:metadata_messenger/engine/dev_engine.dart';
import 'package:metadata_messenger/engine/protocol_engine.dart';
import 'package:metadata_messenger/main.dart';
import 'package:metadata_messenger/provider/provider_routing.dart';
import 'package:metadata_messenger/state/app_state.dart';
import 'package:metadata_messenger/ui/add_buddy_screen.dart';

/// A DevEngine that counts event polls and records the peer label each pairing carried.
class RecordingEngine extends DevEngine {
  int polls = 0;
  final peerLabels = <Uint8List?>[];

  @override
  Future<void> pollEvents() async => polls++;

  @override
  Future<AddBuddyResult> addBuddy({
    required String sharedSecret,
    required BuddyRole role,
    Uint8List? peerNotifyLabel,
  }) {
    peerLabels.add(peerNotifyLabel);
    return super.addBuddy(sharedSecret: sharedSecret, role: role);
  }
}

/// A RoutedSession that records calls; `stepGate` lets a test hold a step in flight.
class FakeSession implements RoutedSession {
  final starts = <int>[];
  final steps = <int>[];
  int collected = 0;
  Completer<void>? stepGate;
  bool failSteps = false;

  @override
  Future<void> startAt(int nowMillis) async => starts.add(nowMillis);

  @override
  Future<void> step(int nowMillis) async {
    steps.add(nowMillis);
    if (failSteps) throw StateError('provider unreachable');
    await stepGate?.future;
  }

  @override
  Future<int> collectAway() async => ++collected;
}

void main() {
  group('ProviderRouting', () {
    test(
      'start registers once, at the current time, and begins stepping',
      () async {
        final session = FakeSession();
        final routing = ProviderRouting(
          RecordingEngine(),
          session,
          now: () => 42_000,
        );
        await routing.start();
        await routing.start();
        expect(session.starts, [42_000], reason: 'registered exactly once');
        expect(routing.running, isTrue);
        routing.dispose();
        expect(routing.running, isFalse);
      },
    );

    test('a step advances the session, then pulls the engine events', () async {
      final engine = RecordingEngine();
      final session = FakeSession();
      var t = 1000;
      final routing = ProviderRouting(engine, session, now: () => t);
      await routing.stepOnce();
      t = 1250;
      await routing.stepOnce();
      expect(session.steps, [1000, 1250]);
      expect(engine.polls, 2);
    });

    test(
      'steps never overlap: a step while one is in flight does nothing',
      () async {
        final engine = RecordingEngine();
        final session = FakeSession()..stepGate = Completer<void>();
        final routing = ProviderRouting(engine, session, now: () => 5);
        final first = routing.stepOnce(); // held in flight by the gate
        await routing.stepOnce(); // returns at once
        expect(session.steps.length, 1);
        session.stepGate!.complete();
        await first;
        expect(engine.polls, 1);
      },
    );

    test(
      'a failing step never escapes, and the next step runs normally',
      () async {
        final engine = RecordingEngine();
        final session = FakeSession()..failSteps = true;
        final routing = ProviderRouting(engine, session, now: () => 5);
        await routing.stepOnce(); // must not throw
        session.failSteps = false;
        await routing.stepOnce();
        expect(session.steps.length, 2);
        expect(
          engine.polls,
          1,
          reason: 'events are pulled after a successful step',
        );
      },
    );

    test(
      'pause stops stepping; resume collects what was kept, then steps again',
      () async {
        final session = FakeSession();
        final routing = ProviderRouting(
          RecordingEngine(),
          session,
          now: () => 5,
        );
        await routing.resume();
        expect(session.collected, 0, reason: 'nothing to resume before start');
        await routing.start();
        routing.pause();
        expect(routing.running, isFalse);
        await routing.resume();
        expect(session.collected, 1);
        expect(routing.running, isTrue);
        await routing.resume();
        expect(
          session.collected,
          1,
          reason: 'already running: resume is a no-op',
        );
        routing.dispose();
      },
    );

    test('the timer steps the session while running', () async {
      final session = FakeSession();
      final routing = ProviderRouting(
        RecordingEngine(),
        session,
        tick: const Duration(milliseconds: 5),
        now: () => 5,
      );
      await routing.start();
      await Future<void>.delayed(const Duration(milliseconds: 60));
      routing.dispose();
      final n = session.steps.length;
      expect(n, greaterThan(2));
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(session.steps.length, n, reason: 'no steps after dispose');
    });
  });

  group('pairing with notify labels', () {
    final label = Uint8List.fromList(List<int>.generate(16, (i) => i));

    Future<void> openAddBuddy(WidgetTester tester, AppState state) async {
      await tester.pumpWidget(MaterialApp(home: AddBuddyScreen(state: state)));
    }

    testWidgets('a routed device shows its own label to give to the buddy', (
      tester,
    ) async {
      await openAddBuddy(
        tester,
        AppState(RecordingEngine(), notifyLabel: label),
      );
      expect(find.textContaining(base64Encode(label)), findsOneWidget);
      expect(find.byKey(const Key('peerLabelField')), findsOneWidget);
    });

    testWidgets('a non-routed device shows no label fields', (tester) async {
      await openAddBuddy(tester, AppState(RecordingEngine()));
      expect(find.byKey(const Key('myNotifyLabel')), findsNothing);
      expect(find.byKey(const Key('peerLabelField')), findsNothing);
    });

    testWidgets("the buddy's label reaches the engine as bytes", (
      tester,
    ) async {
      final engine = RecordingEngine();
      await openAddBuddy(tester, AppState(engine, notifyLabel: label));
      final peer = Uint8List.fromList(utf8.encode('the-peers-label'));
      await tester.enterText(find.byKey(const Key('secretField')), 'secret');
      await tester.enterText(
        find.byKey(const Key('peerLabelField')),
        base64Encode(peer),
      );
      await tester.tap(find.byKey(const Key('startHandshake')));
      await tester.pumpAndSettle();
      expect(engine.peerLabels.single, peer);
    });

    testWidgets('an invalid buddy label is refused before any handshake', (
      tester,
    ) async {
      final engine = RecordingEngine();
      await openAddBuddy(tester, AppState(engine, notifyLabel: label));
      await tester.enterText(find.byKey(const Key('secretField')), 'secret');
      await tester.enterText(
        find.byKey(const Key('peerLabelField')),
        'not base64 !!',
      );
      await tester.tap(find.byKey(const Key('startHandshake')));
      await tester.pumpAndSettle();
      expect(find.text('That buddy label is not valid.'), findsOneWidget);
      expect(engine.peerLabels, isEmpty);
    });
  });

  testWidgets(
    'the app starts routing and pauses / resumes it with the app lifecycle',
    (tester) async {
      final engine = RecordingEngine();
      final session = FakeSession();
      final routing = ProviderRouting(engine, session, now: () => 7);
      await tester.pumpWidget(
        MetadataMessengerApp(engine: engine, routing: routing),
      );
      await tester.pump();
      expect(session.starts, [7]);
      expect(routing.running, isTrue);

      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      expect(
        routing.running,
        isFalse,
        reason: 'hidden: the session stops being stepped',
      );

      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      await tester.pump();
      expect(
        session.collected,
        1,
        reason: 'shown again: what was kept is collected',
      );
      expect(routing.running, isTrue);

      await tester.pumpWidget(
        const SizedBox(),
      ); // unmount: the routing is disposed
      expect(routing.running, isFalse);
    },
  );
}
