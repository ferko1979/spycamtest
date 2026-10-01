SpyCam Desktop Agent (GUI)

What it does:
- Shows a branded window with your logo and runs in the system tray.
- Runs a localhost agent API on 127.0.0.1:8765 (see "Agent API" below).
- Discovers devices on your local network (and flags likely cameras).
- Optionally records disclosed work activity (active app / window title /
  time) and produces a "work verifier" report.
- Opens the Scanner page in your browser.

Intended use: on networks and machines you own or are authorized to manage.

-----------------------------------------------------------------------------
AUTHENTICATION (token)
-----------------------------------------------------------------------------
On first run the agent generates a random API token and stores it in the
config file (see "config_path" shown in the window). Every endpoint except
GET /health requires it, sent as:
    Authorization: Bearer <token>
  or
    X-Agent-Token: <token>
The token is shown in the agent window so you can paste it into the scanner
site's settings. (This replaces the former hard-coded password.)

-----------------------------------------------------------------------------
LICENSING (feature entitlement)
-----------------------------------------------------------------------------
Services are unlocked by license codes verified against a central server:
  Features: scan · active_scan · cameras · activity · alerts · signing
Each code maps (on the server) to a plan + a set of features; a device can
hold several codes and their features are combined.

- Server: cmd/license-server. It loads codes from licenses.json, signs each
  verification with an Ed25519 key (generated on first run), and exposes
  POST /api/verify, GET /api/pubkey, GET /healthz. Device bindings and seat
  limits (max_devices) are enforced and persisted.
    go run ./cmd/license-server -addr :8080 -licenses licenses.json \
        -admin-token "$LICENSE_ADMIN_TOKEN"
  Copy cmd/license-server/licenses.example.json to licenses.json to start.
  The log prints the PUBLIC KEY — pin it in clients. Setting an admin token
  (flag or LICENSE_ADMIN_TOKEN) enables the admin API; leaving it empty
  disables admin endpoints.

- Admin CLI: cmd/license-admin issues, revokes and lists codes over the admin
  API (no hand-editing licenses.json):
    export LICENSE_SERVER=http://localhost:8080 LICENSE_ADMIN_TOKEN=...
    license-admin issue -plan pro -features scan,active_scan,cameras -max-devices 3
    license-admin issue -plan business -features all -expires-days 365
    license-admin list
    license-admin usage           # device check-ins (last-seen) per code
    license-admin audit           # recent admin actions
    license-admin revoke <CODE>   # also: enable, delete
  Admin actions are also appended to an audit log file (-audit, JSON lines).
  Each successful verify records the device's last check-in (usage reporting).
  The agent warns in its window/dashboard when a license expires within 14 days.

- Client (the agent): verifies ON EACH RUN and every 30 minutes while
  running. Responses are Ed25519-signed; the agent checks the signature, a
  per-request nonce (anti-replay), response freshness, and — if you pin the
  server public key — that the key matches, so a rogue local server cannot
  grant features. If the server is briefly unreachable the last-known
  entitlement is kept for a 24h grace window, then it falls back to the base
  (free) feature set ("scan"). Set the server URL, code(s) and (optionally)
  the pinned key in the agent window → Settings → Licensing.

- Gating: unlicensed/locked endpoints return HTTP 402. Passive scan is the
  free base feature; active scan, cameras, activity/reports, alerts and
  report signing require entitling codes. GET /license shows current state.

-----------------------------------------------------------------------------
LOCAL DASHBOARD
-----------------------------------------------------------------------------
The agent serves a bundled scanner dashboard at:
    http://127.0.0.1:8765/            (or /dashboard)
It is same-origin with the agent, so the token is injected automatically —
no pasting required. Use it to scan the network, find likely cameras, view
the activity snapshot, and build/download the work report. Open it from the
agent window ("Open dashboard") or your browser. The remote scanner site can
still use the JSON API below with the token.

-----------------------------------------------------------------------------
SETTINGS (editable in the agent window)
-----------------------------------------------------------------------------
- Server address / port / HTTPS (scanner origin + CORS)
- Activity sampling interval (seconds) and idle threshold (seconds)
- Consent toggles: activity tracking, active network scanning
Settings persist in the config file and apply immediately (the tracker is
reconfigured live).

-----------------------------------------------------------------------------
AGENT API (127.0.0.1:8765)
-----------------------------------------------------------------------------
  GET /health                 liveness + feature flags (no auth)
  GET /networks               local interfaces (IP/CIDR/MAC/gateway)
  GET /scan[?active=1]         devices + networks, enriched with vendor
                              (MAC/OUI), reverse-DNS hostname, and a camera
                              likelihood heuristic. active=1 adds an opt-in
                              TCP sweep (only if active scanning is enabled).
  GET /cameras[?active=1]      scan filtered to likely camera devices
                              (active=1 also RTSP/ONVIF-fingerprints to
                              confirm, adding evidence to each device)
  GET /baseline                known-device count + alert settings
  GET /license                 current license entitlement + per-code status
  (gated endpoints return HTTP 402 when the feature is not licensed)
  GET /activity                current activity snapshot (if tracking is on)
  GET /activity/consent?enable=0   opt OUT of tracking (enabling must be done
                              on-device in the agent window; it cannot be
                              switched on remotely)
  GET /report[?reset=1]        build a work-verifier report (JSON) and append
                              it to local history
  GET /report/history[?n=N]    last N stored reports
  GET /export?format=csv|json  download the current report

-----------------------------------------------------------------------------
CAMERA DETECTION & ALERTS
-----------------------------------------------------------------------------
- Devices are flagged as likely cameras from MAC/OUI vendor, open camera
  ports, and hostname. With active scanning enabled, the agent additionally
  sends an RTSP OPTIONS probe (port 554) and an HTTP/ONVIF banner check to
  CONFIRM cameras and record evidence (server banner, auth realm).
- The agent keeps a baseline of known device MACs. When a new device — or a
  new likely camera — appears, it can POST an alert to a webhook
  (Slack/Discord/automation). Configure the webhook URL and per-kind toggles
  in the agent window; alerts also appear on the dashboard.

-----------------------------------------------------------------------------
WORK-VERIFIER REPORT — CATEGORIES & SIGNING
-----------------------------------------------------------------------------
- Reports group active time into categories (Development, Communication,
  Productivity, Media, Browsing, Other) in addition to per-app detail.
- Each report is signed with a per-install Ed25519 key (generated on first
  run) and carries the signature + public key, so a consumer can verify it
  was produced by this agent and not altered. Idle time is reported
  separately from active time.

-----------------------------------------------------------------------------
ACTIVITY TRACKING — TRANSPARENCY
-----------------------------------------------------------------------------
Activity tracking is OFF by default and only runs with on-device consent:
- Turn it on in the agent window ("I consent...") or from the tray.
- While ON, the tray title shows "Activity tracking ON" and the person on
  the machine can view exactly what is recorded and turn it off anytime.
- It records only the active application, window title, and time (with idle
  detection). It does NOT capture keystrokes, screen contents, clipboard,
  or passwords, and it does not hide from Task Manager / Activity Monitor.
This tool is for disclosed monitoring (self-tracking or workforce tooling
the monitored person is informed about and consents to).

Note (macOS): reading window titles requires granting the app Accessibility
permission (System Settings -> Privacy & Security -> Accessibility).
Note (Linux): window title/idle need X11 tools (xprop, optionally
xprintidle); on Wayland only time totals may be available.

Default site URL:
  http://spycamera.test/scanner

You can change defaults in main.go (siteURL + allowOrigin), or run with args:
  --allow-origin http://spycamera.test
  --site-url http://spycamera.test/scanner
  --host 127.0.0.1
  --port 8765

Close behavior:
- Closing the window exits the app and stops the agent.


Making a windows installable:
requirements go from https://go.dev and git from https://git-scm.com

#############################
#WINDOWS MAKING EXE:
##############################
POWER SHELL commands to build the executable for windows:

cd D:\00000000TONAS\Cegek\spycam-desktop

# clean partial module state
go clean -modcache

# regenerate deps
go mod tidy

# build (GUI)
go build -ldflags "-H=windowsgui" -o spycam-desktop.exe .

# run build script (creates zip)
.\build-windows.ps1
##################################
#Trayversion
#################################
$ErrorActionPreference = "Stop"

go mod tidy
go build -ldflags "-H=windowsgui" -o spycam-agent.exe .

if (-not (Test-Path .\spycam-agent.exe)) { throw "Build did not produce spycam-agent.exe" }
if (-not (Test-Path .\README.txt)) { throw "README.txt missing" }

New-Item -ItemType Directory -Force dist\windows | Out-Null
Copy-Item .\spycam-agent.exe dist\windows\
Copy-Item .\README.txt dist\windows\

Compress-Archive -Path dist\windows\* -DestinationPath spycam-agent-windows.zip -Force
Write-Host "Built spycam-agent-windows.zip"
##################################
# LINUX (dev build)
##################################
Requires GTK3 + WebKitGTK + AppIndicator dev headers, e.g. on Debian/Ubuntu:
  sudo apt-get install libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev

webview_go asks pkg-config for webkit2gtk-4.0; on distros that ship only 4.1,
add shim .pc files that require the 4.1 packages:
  printf 'Name: shim\nVersion: 2.0\nRequires: webkit2gtk-4.1\n' \
    | sudo tee /usr/lib/x86_64-linux-gnu/pkgconfig/webkit2gtk-4.0.pc
  printf 'Name: shim\nVersion: 2.0\nRequires: javascriptcoregtk-4.1\n' \
    | sudo tee /usr/lib/x86_64-linux-gnu/pkgconfig/javascriptcoregtk-4.0.pc
Then: go mod tidy && go build .

Run tests (no GUI needed):
  go test ./...

-----------------------------------------------------------------------------
MOBILE (iOS + Android)
-----------------------------------------------------------------------------
A Flutter app in mobile/ mirrors the scanner + licensing on phones (active
Wi-Fi camera scan, license verification against the same server, and
disclosed Android usage reporting). See mobile/README.md. It is not built in
this repo's CI (no Flutter SDK here); build it with the Flutter toolchain.
