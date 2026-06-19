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
            builder: (context, _) => Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                PrivacyBanner(status: state.privacy),
                if (state.lastNotifiedRound != null)
                  _NotifyIndicator(onDismiss: state.acknowledgeNotified),
                if (state.lastError != null)
                  _ErrorBanner(
                    message: state.lastError!,
                    onDismiss: state.clearError,
                  ),
              ],
            ),
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

/// "Some buddy has mail" (FR-004). Deliberately generic — it never names which
/// buddy wrote; the engine drives retrieval and only the round is shown.
class _NotifyIndicator extends StatelessWidget {
  const _NotifyIndicator({required this.onDismiss});

  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Theme.of(context).colorScheme.secondaryContainer,
      child: ListTile(
        key: const Key('notifyIndicator'),
        dense: true,
        leading: const Icon(Icons.mark_email_unread_outlined),
        title: const Text('Mail waiting'),
        subtitle: const Text('A buddy wrote — which one is hidden'),
        trailing: IconButton(
          icon: const Icon(Icons.close),
          onPressed: onDismiss,
        ),
      ),
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({required this.message, required this.onDismiss});

  final String message;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Theme.of(context).colorScheme.errorContainer,
      child: ListTile(
        key: const Key('errorBanner'),
        dense: true,
        leading: const Icon(Icons.error_outline),
        title: Text(message),
        trailing: IconButton(
          icon: const Icon(Icons.close),
          onPressed: onDismiss,
        ),
      ),
    );
  }
}
