#!/usr/bin/env bash
set -euo pipefail

# --- Config (edit these) ---
APP_NAME="SpyCam Agent"
BIN_NAME="spycam-agent"
BUNDLE_ID="com.spycam.agent"
VERSION="${VERSION:-1.0.0}"
BUILD_DIR="build/macos"
ICON_PNG="assets/icon.png"

# Optional signing/notarization:
#   export CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
#   export NOTARY_PROFILE="notarytool-profile-name"   # created via: xcrun notarytool store-credentials ...
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:-}"
NOTARY_PROFILE="${NOTARY_PROFILE:-}"

# If you want a tray-only agent (no Dock icon), keep LSUIElement=true.
# If you want it to show in Dock, set this to false.
LSUIELEMENT="${LSUIELEMENT:-true}"

# --- Preflight ---
command -v go >/dev/null 2>&1 || { echo "go not found"; exit 1; }
command -v lipo >/dev/null 2>&1 || { echo "lipo not found (install Xcode CLT)"; exit 1; }
command -v sips >/dev/null 2>&1 || { echo "sips not found"; exit 1; }
command -v iconutil >/dev/null 2>&1 || { echo "iconutil not found"; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/bin"

echo "==> Building (arm64)…"
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w" -o "$BUILD_DIR/bin/${BIN_NAME}-arm64" .

echo "==> Building (amd64)…"
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" -o "$BUILD_DIR/bin/${BIN_NAME}-amd64" .

echo "==> Creating universal binary…"
lipo -create \
  "$BUILD_DIR/bin/${BIN_NAME}-arm64" \
  "$BUILD_DIR/bin/${BIN_NAME}-amd64" \
  -output "$BUILD_DIR/bin/${BIN_NAME}"

# --- Build .app bundle structure ---
APP_DIR="$BUILD_DIR/${APP_NAME}.app"
CONTENTS="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RES_DIR="$CONTENTS/Resources"

mkdir -p "$MACOS_DIR" "$RES_DIR"
cp "$BUILD_DIR/bin/${BIN_NAME}" "$MACOS_DIR/${BIN_NAME}"
chmod +x "$MACOS_DIR/${BIN_NAME}"

# --- Generate .icns from your PNG ---
if [[ -f "$ICON_PNG" ]]; then
  echo "==> Generating .icns…"
  ICONSET="$BUILD_DIR/AppIcon.iconset"
  rm -rf "$ICONSET"
  mkdir -p "$ICONSET"

  # iconutil expects these names/sizes
  sips -z 16 16     "$ICON_PNG" --out "$ICONSET/icon_16x16.png" >/dev/null
  sips -z 32 32     "$ICON_PNG" --out "$ICONSET/icon_16x16@2x.png" >/dev/null
  sips -z 32 32     "$ICON_PNG" --out "$ICONSET/icon_32x32.png" >/dev/null
  sips -z 64 64     "$ICON_PNG" --out "$ICONSET/icon_32x32@2x.png" >/dev/null
  sips -z 128 128   "$ICON_PNG" --out "$ICONSET/icon_128x128.png" >/dev/null
  sips -z 256 256   "$ICON_PNG" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
  sips -z 256 256   "$ICON_PNG" --out "$ICONSET/icon_256x256.png" >/dev/null
  sips -z 512 512   "$ICON_PNG" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
  sips -z 512 512   "$ICON_PNG" --out "$ICONSET/icon_512x512.png" >/dev/null
  sips -z 1024 1024 "$ICON_PNG" --out "$ICONSET/icon_512x512@2x.png" >/dev/null

  iconutil -c icns "$ICONSET" -o "$RES_DIR/AppIcon.icns"
else
  echo "WARN: $ICON_PNG not found; app will have no Finder icon"
fi

# --- Info.plist ---
echo "==> Writing Info.plist…"
cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>

  <key>CFBundleDisplayName</key>
  <string>${APP_NAME}</string>

  <key>CFBundleIdentifier</key>
  <string>${BUNDLE_ID}</string>

  <key>CFBundleVersion</key>
  <string>${VERSION}</string>

  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>

  <key>CFBundleExecutable</key>
  <string>${BIN_NAME}</string>

  <key>CFBundlePackageType</key>
  <string>APPL</string>

  <key>CFBundleIconFile</key>
  <string>AppIcon</string>

  <key>LSUIElement</key>
  <$LSUIELEMENT/>

  <key>NSHighResolutionCapable</key>
  <true/>

  <!-- Recommended when accessing/discovering devices on the local network -->
  <key>NSLocalNetworkUsageDescription</key>
  <string>SpyCam Agent scans your local network to discover nearby devices.</string>
</dict>
</plist>
PLIST

# --- Codesign (optional) ---
if [[ -n "$CODESIGN_IDENTITY" ]]; then
  echo "==> Codesigning with: $CODESIGN_IDENTITY"
  # --deep is convenient; if you later embed frameworks/helpers, it helps sign them too.
  codesign --force --deep --options runtime --timestamp \
    --sign "$CODESIGN_IDENTITY" \
    "$APP_DIR"
else
  echo "INFO: CODESIGN_IDENTITY not set; skipping codesign (Gatekeeper will warn on other machines)."
fi

# --- Notarize + staple (optional; requires codesign) ---
if [[ -n "$NOTARY_PROFILE" ]]; then
  echo "==> Notarizing via notarytool profile: $NOTARY_PROFILE"
  ZIP_PATH="$BUILD_DIR/${APP_NAME}.zip"
  /usr/bin/ditto -c -k --keepParent "$APP_DIR" "$ZIP_PATH"

  xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$APP_DIR"
else
  echo "INFO: NOTARY_PROFILE not set; skipping notarization. (Use notarytool for modern notarization.)"
fi

# --- Create DMG (optional convenience) ---
echo "==> Creating DMG…"
DMG_PATH="$BUILD_DIR/${APP_NAME}-${VERSION}.dmg"
hdiutil create -volname "$APP_NAME" -srcfolder "$APP_DIR" -ov -format UDZO "$DMG_PATH" >/dev/null

echo "==> Done:"
echo "  App: $APP_DIR"
echo "  DMG: $DMG_PATH"