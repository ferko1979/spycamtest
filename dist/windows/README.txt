SpyCam Desktop Agent (GUI)

What it does:
- Shows a branded window with your logo
- Runs a localhost agent API on 127.0.0.1:8765:
    GET /health
    GET /scan
- Opens the Scanner page in your browser (where results are saved automatically)

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


WINDOWS MAKING EXE:
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