import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:metadata_messenger/engine/dev_engine.dart';
import 'package:metadata_messenger/engine/protocol_engine.dart';
import 'package:metadata_messenger/main.dart';

void main() {
  testWidgets('shows the DEV, NO METADATA PRIVACY banner on launch',
      (tester) async {
    await tester.pumpWidget(MetadataMessengerApp(engine: DevEngine()));
    await tester.pump(); // let the privacy status microtask flush
    expect(find.text(devNoPrivacyLabel), findsOneWidget);
    expect(find.text('No conversations yet.\nAdd a buddy to start.'),
        findsOneWidget);
  });

  testWidgets('add-buddy flow surfaces a safety number and creates a conversation',
      (tester) async {
    await tester.pumpWidget(MetadataMessengerApp(engine: DevEngine()));
    await tester.pump();

    await tester.tap(find.byKey(const Key('addBuddyFab')));
    await tester.pumpAndSettle();

    await tester.enterText(find.byKey(const Key('secretField')), 'shared-secret');
    await tester.tap(find.byKey(const Key('startHandshake')));
    await tester.pumpAndSettle();

    // Safety number is shown for out-of-band comparison.
    expect(find.byKey(const Key('safetyNumber')), findsOneWidget);

    await tester.tap(find.byKey(const Key('confirmMatch')));
    await tester.pumpAndSettle();

    // Back on home, the confirmed conversation appears.
    expect(find.text('Confirmed'), findsOneWidget);
  });

  testWidgets('sending a message renders it in the conversation', (tester) async {
    final engine = DevEngine();
    await tester.pumpWidget(MetadataMessengerApp(engine: engine));
    await tester.pump();

    await tester.tap(find.byKey(const Key('addBuddyFab')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('secretField')), 's');
    await tester.tap(find.byKey(const Key('startHandshake')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('confirmMatch')));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Confirmed'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byKey(const Key('messageInput')), 'hello there');
    await tester.tap(find.byKey(const Key('sendButton')));
    await tester.pumpAndSettle();

    expect(find.text('hello there'), findsWidgets);
  });

  testWidgets('notify indicator appears on a notified round and dismisses (FR-004)',
      (tester) async {
    final engine = DevEngine();
    await tester.pumpWidget(MetadataMessengerApp(engine: engine));
    await tester.pump();

    expect(find.byKey(const Key('notifyIndicator')), findsNothing);

    await engine.tick(roundId: 1); // "some buddy has mail"
    await tester.pump();
    expect(find.byKey(const Key('notifyIndicator')), findsOneWidget);
    // Must not name a buddy.
    expect(find.text('A buddy wrote — which one is hidden'), findsOneWidget);

    await tester.tap(find.descendant(
      of: find.byKey(const Key('notifyIndicator')),
      matching: find.byIcon(Icons.close),
    ));
    await tester.pump();
    expect(find.byKey(const Key('notifyIndicator')), findsNothing);
  });
}
