import 'package:flutter/material.dart';
import 'package:network_info_plus/network_info_plus.dart';

import '../theme.dart';
import '../license/license.dart';
import '../scan/scan.dart';

class ScanScreen extends StatefulWidget {
  final LicenseManager manager;
  const ScanScreen({super.key, required this.manager});

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  final _devices = <Device>[];
  bool _scanning = false;
  String _status = '';

  Future<void> _scan() async {
    if (!widget.manager.has(Features.activeScan)) {
      setState(() => _status = 'Active scan requires a license that includes "active_scan".');
      return;
    }
    setState(() {
      _scanning = true;
      _devices.clear();
      _status = 'Finding your network…';
    });
    final ip = await NetworkInfo().getWifiIP();
    if (ip == null) {
      setState(() {
        _scanning = false;
        _status = 'No Wi-Fi network detected.';
      });
      return;
    }
    setState(() => _status = 'Scanning ${ip.substring(0, ip.lastIndexOf('.'))}.0/24…');
    await Scanner().scan(ip, onDevice: (d) {
      if (!mounted) return;
      setState(() => _devices.add(d));
    });
    if (!mounted) return;
    setState(() {
      _scanning = false;
      final cams = _devices.where((d) => d.likelyCamera).length;
      _status = '${_devices.length} device(s), $cams likely camera(s).';
    });
  }

  @override
  Widget build(BuildContext context) {
    final cams = _devices.where((d) => d.likelyCamera).length;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(
          children: [
            Expanded(child: _kpi('Devices', '${_devices.length}')),
            const SizedBox(width: 12),
            Expanded(child: _kpi('Likely cameras', '$cams')),
          ],
        ),
        const SizedBox(height: 14),
        FilledButton.icon(
          onPressed: _scanning ? null : _scan,
          icon: _scanning
              ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.radar),
          label: Text(_scanning ? 'Scanning…' : 'Scan my network for cameras'),
        ),
        const SizedBox(height: 8),
        Text(_status, style: const TextStyle(color: Brand.muted, fontSize: 13)),
        const SizedBox(height: 8),
        const Text(
          'Scans only the Wi-Fi network this device is on. Use on networks you own or are authorized to scan.',
          style: TextStyle(color: Brand.muted, fontSize: 12),
        ),
        const Divider(height: 28, color: Brand.border),
        for (final d in _devices) _deviceTile(d),
      ],
    );
  }

  Widget _kpi(String label, String value) => Card(
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(value, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w800)),
              Text(label, style: const TextStyle(color: Brand.muted, fontSize: 12)),
            ],
          ),
        ),
      );

  Widget _deviceTile(Device d) => Card(
        child: ListTile(
          title: Text(d.ip, style: const TextStyle(fontWeight: FontWeight.w700)),
          subtitle: Text(
            'ports: ${d.openPorts.join(', ')}'
            '${d.reasons.isNotEmpty ? '\n${d.reasons.join('; ')}' : ''}',
            style: const TextStyle(color: Brand.muted, fontSize: 12),
          ),
          isThreeLine: d.reasons.isNotEmpty,
          trailing: d.likelyCamera
              ? Container(
                  padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 3),
                  decoration: BoxDecoration(
                    border: Border.all(color: Brand.danger),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: const Text('camera', style: TextStyle(color: Brand.danger, fontSize: 11)),
                )
              : null,
        ),
      );
}
