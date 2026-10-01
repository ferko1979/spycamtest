import 'dart:async';
import 'dart:io';

/// Ports commonly exposed by IP cameras / NVRs (mirrors the Go netscan list).
const cameraPorts = [554, 8554, 80, 8000, 37777, 34567];

const _cameraPortMeaning = {
  554: 'RTSP (554)',
  8554: 'RTSP-alt (8554)',
  80: 'HTTP (80)',
  8000: 'camera HTTP (8000)',
  37777: 'Dahua control (37777)',
  34567: 'NVR control (34567)',
};

/// A host discovered on the local network.
class Device {
  final String ip;
  final List<int> openPorts;
  bool likelyCamera;
  bool rtsp;
  String? rtspServer;
  final List<String> reasons;

  Device(this.ip)
      : openPorts = [],
        likelyCamera = false,
        rtsp = false,
        reasons = [];
}

/// Scanner performs an active TCP-connect sweep of the local /24 subnet and
/// fingerprints likely cameras. Active (sends packets) — use only on networks
/// you own or are authorized to scan. The caller gates this behind the
/// active-scan entitlement and an explicit user action.
class Scanner {
  final Duration connectTimeout;
  final int concurrency;

  Scanner({
    this.connectTimeout = const Duration(milliseconds: 600),
    this.concurrency = 48,
  });

  /// Enumerate usable /24 hosts for a local IPv4 like "192.168.1.37".
  static List<String> subnetHosts(String localIp) {
    final parts = localIp.split('.');
    if (parts.length != 4) return const [];
    final prefix = '${parts[0]}.${parts[1]}.${parts[2]}.';
    return [for (var i = 1; i <= 254; i++) '$prefix$i'];
  }

  /// Scan the subnet of [localIp], reporting devices as they are found via
  /// [onDevice]. Returns the full list when complete.
  Future<List<Device>> scan(String localIp, {void Function(Device)? onDevice}) async {
    final hosts = subnetHosts(localIp);
    final found = <String, Device>{};
    final queue = StreamController<String>();
    final results = <Future<void>>[];

    Future<void> worker() async {
      await for (final ip in queue.stream) {
        final open = <int>[];
        for (final p in cameraPorts) {
          if (await _canConnect(ip, p)) open.add(p);
        }
        if (open.isEmpty) continue;
        final d = Device(ip)..openPorts.addAll(open);
        for (final p in open) {
          final m = _cameraPortMeaning[p];
          if (m != null) d.reasons.add('open $m');
        }
        await _fingerprint(d);
        _classify(d);
        found[ip] = d;
        onDevice?.call(d);
      }
    }

    for (var i = 0; i < concurrency; i++) {
      results.add(worker());
    }
    for (final h in hosts) {
      queue.add(h);
    }
    await queue.close();
    await Future.wait(results);

    final list = found.values.toList()..sort((a, b) => a.ip.compareTo(b.ip));
    return list;
  }

  Future<bool> _canConnect(String ip, int port) async {
    try {
      final s = await Socket.connect(ip, port, timeout: connectTimeout);
      s.destroy();
      return true;
    } catch (_) {
      return false;
    }
  }

  /// RTSP OPTIONS probe to confirm a camera stream endpoint.
  Future<void> _fingerprint(Device d) async {
    if (!d.openPorts.contains(554) && !d.openPorts.contains(8554)) return;
    final port = d.openPorts.contains(554) ? 554 : 8554;
    try {
      final s = await Socket.connect(d.ip, port, timeout: connectTimeout);
      s.write('OPTIONS rtsp://${d.ip}:$port/ RTSP/1.0\r\nCSeq: 1\r\n\r\n');
      final data = await s
          .timeout(connectTimeout, onTimeout: (sink) => sink.close())
          .fold<List<int>>(<int>[], (a, b) => a..addAll(b));
      s.destroy();
      final text = String.fromCharCodes(data);
      if (text.contains('RTSP/')) {
        d.rtsp = true;
        d.reasons.add('RTSP OPTIONS responded');
        final m = RegExp(r'Server:\s*(.+)', caseSensitive: false).firstMatch(text);
        if (m != null) d.rtspServer = m.group(1)?.trim();
      }
    } catch (_) {
      // best-effort
    }
  }

  void _classify(Device d) {
    d.likelyCamera = d.rtsp ||
        d.openPorts.contains(37777) ||
        d.openPorts.contains(34567) ||
        (d.openPorts.contains(8000) && d.openPorts.contains(80));
  }
}
