import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';

import 'theme.dart';
import 'widgets/logo.dart';
import 'license/license.dart';
import 'screens/scan_screen.dart';
import 'screens/usage_screen.dart';
import 'screens/license_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final settings = await Settings.load();
  runApp(SpyCamApp(settings: settings));
}

/// Settings persists the license config and a stable device id.
class Settings {
  final SharedPreferences _p;
  Settings(this._p);

  static Future<Settings> load() async {
    final p = await SharedPreferences.getInstance();
    if (p.getString('device_id') == null) {
      await p.setString('device_id', Uuid().v4());
    }
    return Settings(p);
  }

  String get deviceId => _p.getString('device_id') ?? '';
  String get serverUrl => _p.getString('license_server') ?? '';
  List<String> get codes => _p.getStringList('license_codes') ?? const [];
  String get pinnedKey => _p.getString('license_pubkey') ?? '';

  Future<void> save({String? serverUrl, List<String>? codes, String? pinnedKey}) async {
    if (serverUrl != null) await _p.setString('license_server', serverUrl.trim());
    if (codes != null) await _p.setStringList('license_codes', codes);
    if (pinnedKey != null) await _p.setString('license_pubkey', pinnedKey.trim());
  }
}

class SpyCamApp extends StatefulWidget {
  final Settings settings;
  const SpyCamApp({super.key, required this.settings});

  @override
  State<SpyCamApp> createState() => _SpyCamAppState();
}

class _SpyCamAppState extends State<SpyCamApp> {
  late final LicenseManager manager;

  @override
  void initState() {
    super.initState();
    manager = LicenseManager(
      codes: widget.settings.codes,
      clientFactory: () => LicenseClient(
        serverUrl: widget.settings.serverUrl,
        deviceId: widget.settings.deviceId,
        pinnedPublicKey: widget.settings.pinnedKey.isEmpty ? null : widget.settings.pinnedKey,
      ),
    );
    manager.start();
  }

  @override
  void dispose() {
    manager.dispose();
    super.dispose();
  }

  void _onSettingsChanged() {
    manager.codes = widget.settings.codes;
    manager.refresh();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SpyCam',
      theme: buildTheme(),
      debugShowCheckedModeBanner: false,
      home: HomeShell(
        settings: widget.settings,
        manager: manager,
        onSettingsChanged: _onSettingsChanged,
      ),
    );
  }
}

class HomeShell extends StatefulWidget {
  final Settings settings;
  final LicenseManager manager;
  final VoidCallback onSettingsChanged;
  const HomeShell({
    super.key,
    required this.settings,
    required this.manager,
    required this.onSettingsChanged,
  });

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _tab = 0;

  @override
  void initState() {
    super.initState();
    widget.manager.addListener(_refresh);
  }

  @override
  void dispose() {
    widget.manager.removeListener(_refresh);
    super.dispose();
  }

  void _refresh() => setState(() {});

  @override
  Widget build(BuildContext context) {
    final ent = widget.manager.entitlement;
    final screens = [
      ScanScreen(manager: widget.manager),
      UsageScreen(manager: widget.manager),
      LicenseScreen(
        settings: widget.settings,
        manager: widget.manager,
        onSaved: widget.onSettingsChanged,
      ),
    ];

    return Scaffold(
      appBar: AppBar(
        backgroundColor: Brand.surface2,
        title: Row(
          children: [
            const SpyCamLogo(size: 28),
            const SizedBox(width: 10),
            const Text('SpyCam', style: TextStyle(fontWeight: FontWeight.w800)),
            const Spacer(),
            _PlanChip(ent: ent),
          ],
        ),
      ),
      body: screens[_tab],
      bottomNavigationBar: NavigationBar(
        backgroundColor: Brand.surface2,
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.radar), label: 'Scan'),
          NavigationDestination(icon: Icon(Icons.timelapse), label: 'Usage'),
          NavigationDestination(icon: Icon(Icons.verified_user), label: 'License'),
        ],
      ),
    );
  }
}

class _PlanChip extends StatelessWidget {
  final Entitlement ent;
  const _PlanChip({required this.ent});

  @override
  Widget build(BuildContext context) {
    final plans = ent.plans;
    final label = plans.isNotEmpty ? plans.join('+') : (ent.features.length > 1 ? 'licensed' : 'free');
    final color = plans.isNotEmpty ? Brand.ok : Brand.muted;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        border: Border.all(color: color),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(label, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w700)),
    );
  }
}
