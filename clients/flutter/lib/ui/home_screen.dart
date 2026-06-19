import 'package:flutter/material.dart';

import '../state/app_state.dart';
import 'add_buddy_screen.dart';
import 'conversation_screen.dart';
import 'privacy_banner.dart';

/// Home: the mandatory privacy banner + the multi-conversation buddy list
/// (T036). Tapping a buddy opens its conversation; the FAB starts the
/// add-buddy handshake.
class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key, required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Messages')),
      body: Column(
        children: [
          ListenableBuilder(
            listenable: state,
            builder: (context, _) => PrivacyBanner(status: state.privacy),
          ),
          Expanded(
            child: ListenableBuilder(
              listenable: state,
              builder: (context, _) {
                final buddies = state.buddies;
                if (buddies.isEmpty) {
                  return const Center(
                    child: Text('No conversations yet.\nAdd a buddy to start.',
                        textAlign: TextAlign.center),
                  );
                }
                return ListView.separated(
                  itemCount: buddies.length,
                  separatorBuilder: (_, _) => const Divider(height: 1),
                  itemBuilder: (context, i) {
                    final b = buddies[i];
                    return ListTile(
                      leading: CircleAvatar(
                        child: Text(b.displayName.isEmpty
                            ? '?'
                            : b.displayName[0].toUpperCase()),
                      ),
                      title: Text(b.displayName),
                      subtitle:
                          Text(b.confirmed ? 'Confirmed' : 'Pending'),
                      onTap: () => Navigator.of(context).push(
                        MaterialPageRoute(
                          builder: (_) =>
                              ConversationScreen(state: state, buddy: b),
                        ),
                      ),
                    );
                  },
                );
              },
            ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        key: const Key('addBuddyFab'),
        icon: const Icon(Icons.person_add),
        label: const Text('Add buddy'),
        onPressed: () => Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => AddBuddyScreen(state: state)),
        ),
      ),
    );
  }
}
