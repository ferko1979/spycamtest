import 'dart:io' show Platform;
import 'package:flutter/services.dart';

/// UsageEntry is one app's foreground time over the query window.
class UsageEntry {
  final String app; // package name (Android)
  final double seconds;
  UsageEntry(this.app, this.seconds);
}

/// UsageService exposes DISCLOSED app-usage reporting.
///
/// Transparency / platform reality:
///  - Android: foreground usage is read via UsageStatsManager through a
///    platform channel. It requires the user to grant "Usage access" in
///    system Settings — an explicit, OS-level consent gate — and this app
///    does not hide that it is running. It is for self-tracking or disclosed
///    workforce use only; it never captures keystrokes, screen or content.
///  - iOS: Apple's sandbox does NOT allow an app to read other apps' usage,
///    so cross-app "work verifier" data is unavailable by design. The usage
///    screen explains this; only this app's own in-session time is shown.
class UsageService {
  static const _channel = MethodChannel('spycam/usage');

  bool get supported => Platform.isAndroid;

  /// Whether the OS "Usage access" permission has been granted (Android).
  Future<bool> hasPermission() async {
    if (!Platform.isAndroid) return false;
    try {
      return await _channel.invokeMethod<bool>('hasPermission') ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Open the system "Usage access" settings so the user can grant it.
  Future<void> requestPermission() async {
    if (!Platform.isAndroid) return;
    try {
      await _channel.invokeMethod('openUsageAccessSettings');
    } on PlatformException {
      // no-op
    }
  }

  /// Foreground usage for the last [sinceHours] hours (Android only).
  Future<List<UsageEntry>> query({int sinceHours = 24}) async {
    if (!Platform.isAndroid) return const [];
    try {
      final raw = await _channel.invokeListMethod<dynamic>('query', {'since_hours': sinceHours});
      if (raw == null) return const [];
      return raw
          .cast<Map>()
          .map((m) => UsageEntry(
                (m['app'] ?? '').toString(),
                (m['seconds'] as num?)?.toDouble() ?? 0,
              ))
          .where((e) => e.seconds > 0)
          .toList()
        ..sort((a, b) => b.seconds.compareTo(a.seconds));
    } on PlatformException {
      return const [];
    }
  }
}
