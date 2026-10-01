import 'package:flutter/material.dart';

import '../main.dart' show Settings;
import '../theme.dart';
import '../license/license.dart';

class LicenseScreen extends StatefulWidget {
  final Settings settings;
  final LicenseManager manager;
  final VoidCallback onSaved;
  const LicenseScreen({
    super.key,
    required this.settings,
    required this.manager,
    required this.onSaved,
  });

  @override
  State<LicenseScreen> createState() => _LicenseScreenState();
}

class _LicenseScreenState extends State<LicenseScreen> {
  late final TextEditingController _url;
  late final TextEditingController _codes;
  late final TextEditingController _key;

  @override
  void initState() {
    super.initState();
    _url = TextEditingController(text: widget.settings.serverUrl);
    _codes = TextEditingController(text: widget.settings.codes.join('\n'));
    _key = TextEditingController(text: widget.settings.pinnedKey);
  }

  @override
  void dispose() {
    _url.dispose();
    _codes.dispose();
    _key.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final codes = _codes.text
        .split(RegExp(r'[\n,; ]+'))
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
    await widget.settings.save(serverUrl: _url.text, codes: codes, pinnedKey: _key.text);
    widget.onSaved();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Saved — re-verifying license…')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final ent = widget.manager.entitlement;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Entitlement', style: TextStyle(fontWeight: FontWeight.w800)),
                const SizedBox(height: 8),
                _row('Plan(s)', ent.plans.isEmpty ? '—' : ent.plans.join(', ')),
                _row('Features', ent.features.isEmpty ? '—' : ent.features.join(', ')),
                _row('Device', widget.settings.deviceId),
                if (ent.inGrace)
                  const _Badge('using cached license (server unreachable)', Brand.warn),
                if (ent.degraded && !ent.inGrace)
                  const _Badge('unlicensed / base features only', Brand.muted),
                if (ent.soonestExpiry != null) _expiry(ent.soonestExpiry!),
                if (ent.lastError != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 6),
                    child: Text('last error: ${ent.lastError}',
                        style: const TextStyle(color: Brand.muted, fontSize: 11)),
                  ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 14),
        _field('License server URL', _url, hint: 'https://license.example.com'),
        _field('License code(s) — one per line', _codes, maxLines: 4),
        _field('Pinned server public key (optional)', _key, hint: 'base64 — pins server identity'),
        const SizedBox(height: 12),
        FilledButton(onPressed: _save, child: const Text('Save & verify')),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: () => widget.manager.refresh(),
          icon: const Icon(Icons.refresh),
          label: const Text('Re-verify now'),
        ),
      ],
    );
  }

  Widget _expiry(DateTime exp) {
    final days = exp.difference(DateTime.now()).inDays;
    final soon = days <= 14;
    return Padding(
      padding: const EdgeInsets.only(top: 6),
      child: Text(
        'Expires: ${exp.toIso8601String().substring(0, 10)}'
        '${soon ? '  ⚠ in ${days < 0 ? 'expired' : '${days}d'}' : ''}',
        style: TextStyle(color: soon ? Brand.warn : Brand.muted, fontSize: 12),
      ),
    );
  }

  Widget _row(String k, String v) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(width: 90, child: Text(k, style: const TextStyle(color: Brand.muted, fontSize: 12))),
            Expanded(child: Text(v, style: const TextStyle(fontSize: 12))),
          ],
        ),
      );

  Widget _field(String label, TextEditingController c, {String? hint, int maxLines = 1}) => Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label, style: const TextStyle(color: Brand.muted, fontSize: 12)),
            const SizedBox(height: 6),
            TextField(
              controller: c,
              maxLines: maxLines,
              style: const TextStyle(fontSize: 13),
              decoration: InputDecoration(
                hintText: hint,
                isDense: true,
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(11)),
              ),
            ),
          ],
        ),
      );
}

class _Badge extends StatelessWidget {
  final String text;
  final Color color;
  const _Badge(this.text, this.color);
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(top: 8),
        child: Text(text, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600)),
      );
}
