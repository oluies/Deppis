import 'package:flutter/material.dart';

import '../engine/protocol_engine.dart';

/// Mandatory build/privacy label (FR-016, Constitution IV).
///
/// When `metadataPrivate == false` the banner is loud and red: the active
/// backend is dev/stub (or attestation has not passed), so the app gives NO
/// metadata privacy and the user must know.
class PrivacyBanner extends StatelessWidget {
  const PrivacyBanner({super.key, required this.status});

  final PrivacyStatus? status;

  @override
  Widget build(BuildContext context) {
    final s = status;
    final private = s?.metadataPrivate ?? false;
    final label = s?.label ?? devNoPrivacyLabel;
    final color = private ? Colors.green.shade700 : Colors.red.shade700;
    return Material(
      color: color,
      child: SizedBox(
        width: double.infinity,
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 12),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(private ? Icons.lock : Icons.warning_amber_rounded,
                  size: 16, color: Colors.white),
              const SizedBox(width: 8),
              Flexible(
                child: Text(
                  label,
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 0.5,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
