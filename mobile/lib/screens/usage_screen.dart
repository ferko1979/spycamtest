import 'dart:io' show Platform;
import 'package:flutter/material.dart';

import '../theme.dart';
import '../license/license.dart';
import '../usage/usage.dart';

class UsageScreen extends StatefulWidget {
  final LicenseManager manager;
  const UsageScreen({super.key, required this.manager});

  @override
  State<UsageScreen> createState() => _UsageScreenState();
}

class _UsageScreenState extends State<UsageScreen> {
  final _svc = UsageService();
  List<UsageEntry> _entries = const [];
  bool _granted = false;

  @override
  void initState() {
    super.initState();
    _check();
  }

  Future<void> _check() async {
    final g = await _svc.hasPermission();
    final e = g ? await _svc.query() : const <UsageEntry>[];
    if (!mounted) return;
    setState(() {
      _granted = g;
      _entries = e;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.manager.has(Features.activity)) {
      return _notice(
        Icons.lock_outline,
        'Activity tracking is a licensed feature. Enter a license code that includes "activity" on the License tab.',
      );
    }
    if (Platform.isIOS) {
      return _notice(
        Icons.info_outline,
        'On iOS, Apple\'s sandbox does not allow an app to read other apps\' usage, so a cross-app work report is not available. '
        'This is by design and applies to every app on the platform.',
      );
    }
    if (!_svc.supported) {
      return _notice(Icons.info_outline, 'Usage reporting is available on Android only.');
    }

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Disclosed usage', style: TextStyle(fontWeight: FontWeight.w800)),
                const SizedBox(height: 6),
                const Text(
                  'Shows your own foreground app time for a work report. Requires the system "Usage access" '
                  'permission, which you grant explicitly in Settings. No keystrokes, screen or content are captured, '
                  'and this app does not hide that it is running.',
                  style: TextStyle(color: Brand.muted, fontSize: 12),
                ),
                const SizedBox(height: 12),
                if (!_granted)
                  FilledButton(
                    onPressed: () async {
                      await _svc.requestPermission();
                      await Future.delayed(const Duration(seconds: 1));
                      _check();
                    },
                    child: const Text('Grant "Usage access"'),
                  )
                else
                  OutlinedButton.icon(
                    onPressed: _check,
                    icon: const Icon(Icons.refresh),
                    label: const Text('Refresh'),
                  ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        if (_granted && _entries.isEmpty)
          const Text('No usage recorded in the last 24h.', style: TextStyle(color: Brand.muted)),
        for (final e in _entries) _usageTile(e),
      ],
    );
  }

  Widget _usageTile(UsageEntry e) {
    final mins = (e.seconds / 60).toStringAsFixed(1);
    return Card(
      child: ListTile(
        title: Text(e.app, style: const TextStyle(fontSize: 14)),
        trailing: Text('$mins min', style: const TextStyle(color: Brand.muted)),
      ),
    );
  }

  Widget _notice(IconData icon, String text) => Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, color: Brand.muted, size: 40),
              const SizedBox(height: 14),
              Text(text, textAlign: TextAlign.center, style: const TextStyle(color: Brand.muted)),
            ],
          ),
        ),
      );
}
