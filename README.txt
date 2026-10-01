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
AGENT API (127.0.0.1:8765)
-----------------------------------------------------------------------------
  GET /health                 liveness + feature flags (no auth)
  GET /networks               local interfaces (IP/CIDR/MAC/gateway)
  GET /scan[?active=1]         devices + networks, enriched with vendor
                              (MAC/OUI), reverse-DNS hostname, and a camera
                              likelihood heuristic. active=1 adds an opt-in
                              TCP sweep (only if active scanning is enabled).
  GET /cameras[?active=1]      scan filtered to likely camera devices
  GET /activity                current activity snapshot (if tracking is on)
  GET /activity/consent?enable=0   opt OUT of tracking (enabling must be done
                              on-device in the agent window; it cannot be
                              switched on remotely)
  GET /report[?reset=1]        build a work-verifier report (JSON) and append
                              it to local history
  GET /report/history[?n=N]    last N stored reports
  GET /export?format=csv|json  download the current report

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
