# SpyCam Mobile (iOS + Android)

A Flutter app that mirrors the desktop agent's two objectives on mobile:

- **Network & camera scanner** — an active TCP sweep of the Wi‑Fi network the
  phone is on, with camera‑port detection and RTSP fingerprinting.
- **Licensed features** — verifies license code(s) against the same central
  `license-server` (`/api/verify`), checking the Ed25519 signature, a
  per‑request nonce, response freshness and an optional pinned key; it
  re‑verifies on launch and every 30 minutes, with a 24h offline grace window.
- **Disclosed usage (Android only)** — self/disclosed foreground‑app time for a
  work report, gated behind the OS "Usage access" permission.

> ⚠️ **Not built/verified in this repo's CI container** (no Flutter SDK, Xcode
> or Android SDK here). The Dart code is written to compile against Flutter
> 3.19+/Dart 3.3+, but you must build it on a machine with the toolchains.

## Build

```bash
cd mobile
flutter create --org com.spycam --project-name spycam_mobile .   # generate android/ ios/
flutter pub get
flutter run            # on a connected device/emulator
flutter build apk      # Android
flutter build ios      # iOS (needs Xcode + signing)
```

`flutter create` generates the native `android/` and `ios/` folders without
touching the existing `lib/`, `pubspec.yaml` or `assets/`.

## Privacy / platform posture (important)

This app keeps the same **disclosed‑only** stance as the desktop agent:

- **Scanning** only touches the network the device is already joined to; use it
  on networks you own or are authorized to scan. It is designed for *finding*
  cameras (a pro‑privacy use), not attacking anything.
- **Usage reporting is self/disclosed only.** It is **not** covert monitoring
  of someone else's phone (that would be stalkerware and is out of scope):
  - **Android**: foreground usage comes from `UsageStatsManager`, which only
    works after the user grants **Settings → Usage access** — an explicit,
    OS‑level consent gate. The app does not hide itself and never reads
    keystrokes, screen or content.
  - **iOS**: Apple's sandbox does **not** allow reading other apps' usage, so a
    cross‑app work report is impossible on iOS by design. The Usage tab says so.

## iOS local‑network permission

Add to `ios/Runner/Info.plist` (required for LAN scanning on iOS 14+):

```xml
<key>NSLocalNetworkUsageDescription</key>
<string>SpyCam scans your current Wi‑Fi network to find cameras and devices.</string>
```

## Android: Usage access platform channel

After `flutter create`, add the `usage` method channel to
`android/app/src/main/kotlin/<...>/MainActivity.kt` (see
`android_usage_MainActivity.kt.example` in this folder) and add to
`android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.PACKAGE_USAGE_STATS"
    tools:ignore="ProtectedPermissions" />
<uses-permission android:name="android.permission.INTERNET" />
```

(Declare the `xmlns:tools` namespace on the `<manifest>` element.)

## Structure

```
lib/
  main.dart              app shell, settings (shared_preferences), nav
  theme.dart             brand palette + theme
  widgets/logo.dart      radar+lens mark (CustomPainter, no SVG dep)
  license/license.dart   Claims/SignedResponse, client (sig+nonce+pin+freshness),
                         manager (multi-code union, 30-min refresh, grace)
  scan/scan.dart         subnet sweep + camera ports + RTSP fingerprint
  usage/usage.dart       Android UsageStats via platform channel; iOS limitation
  screens/               scan / usage / license tabs
```
