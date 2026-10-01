package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/getlantern/systray"

	"spycam-tray-agent/internal/activity"
	"spycam-tray-agent/internal/auth"
	"spycam-tray-agent/internal/netscan"
	"spycam-tray-agent/internal/report"
)

func osName() string { return runtime.GOOS }

// updateTrayIndicator makes activity tracking visible from the system tray:
// the tray title/tooltip clearly shows whether monitoring is ON. This is
// part of the transparency contract — the person on the machine can always
// see, from the tray, that tracking is running.
func updateTrayIndicator() {
	on := getRemoteConfig().ActivityConsent
	if on {
		systray.SetTitle("SpyCam Agent — ● Activity tracking ON")
		systray.SetTooltip("SpyCam Agent: activity tracking is ON (app, window title, time). Open the window to view or stop it.")
	} else {
		systray.SetTitle("SpyCam Agent")
		systray.SetTooltip("SpyCam Agent running (network scan). Activity tracking is OFF.")
	}
}

// tracker is the transparent activity tracker. It is created in
// initIntegrations and only accumulates while the user has consented
// (RemoteConfig.ActivityConsent), which is surfaced by a visible tray
// indicator and controllable from the agent window.
var tracker *activity.Tracker

// initIntegrations constructs and starts the activity tracker. Tracking does
// not accumulate until consent is given (default off).
func initIntegrations() {
	cfg := getRemoteConfig()
	tracker = activity.New(activity.NewSampler(), activity.Options{
		Interval:      cfg.SampleInterval(),
		IdleThreshold: cfg.IdleThreshold(),
		Idle:          activity.NewIdle(),
	})
	tracker.SetEnabled(cfg.ActivityConsent)
	tracker.Start()
}

// reconfigureTracker rebuilds the tracker with current config timing while
// preserving consent state and accumulated usage is discarded (a new window
// begins). Called when the user changes sampling settings.
func reconfigureTracker() {
	cfg := getRemoteConfig()
	if tracker != nil {
		tracker.Stop()
	}
	tracker = activity.New(activity.NewSampler(), activity.Options{
		Interval:      cfg.SampleInterval(),
		IdleThreshold: cfg.IdleThreshold(),
		Idle:          activity.NewIdle(),
	})
	tracker.SetEnabled(cfg.ActivityConsent)
	tracker.Start()
	updateTrayIndicator()
}

func stopIntegrations() {
	if tracker != nil {
		tracker.Stop()
	}
}

// ensureToken generates and persists an API token if none exists yet.
func ensureToken() {
	cfg := getRemoteConfig()
	if cfg.Token != "" {
		return
	}
	tok, err := auth.GenerateToken()
	if err != nil {
		logf("token generation failed: %v", err)
		return
	}
	cfg.Token = tok
	if err := saveRemoteConfig(cfg); err != nil {
		logf("token save failed: %v", err)
	}
	applyRemoteConfig(cfg)
}

func getToken() string {
	return getRemoteConfig().Token
}

// setTrackingConsent records the user's consent decision, flips the tracker,
// persists it, and updates the visible tray indicator. Enabling is only ever
// triggered by an on-device action (the agent window or tray menu), never
// silently by the remote site.
func setTrackingConsent(enable bool) {
	cfg := getRemoteConfig()
	cfg.ActivityConsent = enable
	_ = saveRemoteConfig(cfg)
	applyRemoteConfig(cfg)
	if tracker != nil {
		tracker.SetEnabled(enable)
	}
	updateTrayIndicator()
}

// permissionStatus reports whether window-title capture is available on this
// OS, with a human-readable detail/remediation message.
func permissionStatus() (bool, string) { return activity.TitleCapability() }

// openActivityPermission opens the OS permission settings pane (macOS) or is
// a no-op where none applies.
func openActivityPermission() error { return activity.OpenPermissionSettings() }

// saveActivitySettings validates and persists the sampling settings, then
// reconfigures the running tracker.
func saveActivitySettings(intervalSec, idleSec int) error {
	if intervalSec < 1 || intervalSec > 3600 {
		return fmt.Errorf("sample interval must be between 1 and 3600 seconds")
	}
	if idleSec < 10 || idleSec > 86400 {
		return fmt.Errorf("idle threshold must be between 10 and 86400 seconds")
	}
	cfg := getRemoteConfig()
	cfg.SampleIntervalSec = intervalSec
	cfg.IdleThresholdSec = idleSec
	if err := saveRemoteConfig(cfg); err != nil {
		return err
	}
	applyRemoteConfig(cfg)
	reconfigureTracker()
	return nil
}

// authWrap applies bearer-token auth using the current token.
func authWrap(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth.Middleware(getToken(), h)(w, r)
	}
}

// preflight writes CORS headers and handles an OPTIONS request, returning
// true if the request was a preflight that is now complete.
func preflight(w http.ResponseWriter, r *http.Request) bool {
	cors(w, getAllowOrigin())
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// toNetscanDevices converts the agent's scanned devices to netscan.Device.
func toNetscanDevices(devs []Device) []netscan.Device {
	out := make([]netscan.Device, 0, len(devs))
	for _, d := range devs {
		out = append(out, netscan.Device{IP: d.IP, MAC: d.MAC, Hostname: d.Hostname})
	}
	return out
}

func toNetscanNetworks(nets []LanNetwork) []netscan.Network {
	out := make([]netscan.Network, 0, len(nets))
	for _, n := range nets {
		out = append(out, netscan.Network{
			Interface: n.Interface, IP: n.IP, CIDR: n.CIDR, MAC: n.MAC, Gateway: n.Gateway,
		})
	}
	return out
}

// discover runs passive neighbor discovery, enriches it (vendor + reverse
// DNS + camera classification), and optionally runs an opt-in active TCP
// sweep of the local subnets when active is true AND the user has enabled
// active scanning in config.
func discover(active bool) ([]netscan.Device, []netscan.Network, error) {
	devs, err := scanNeighbors()
	if err != nil {
		return nil, nil, err
	}
	nd := toNetscanDevices(devs)
	nn := toNetscanNetworks(collectLanNetworks())

	var openPorts map[string][]int
	if active && getRemoteConfig().ActiveScanConsent {
		openPorts = map[string][]int{}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		for _, n := range nn {
			for _, pr := range netscan.Sweep(ctx, n.CIDR, netscan.SweepOptions{}) {
				openPorts[pr.IP] = pr.OpenPorts
			}
		}
	}

	netscan.Enrich(nd, openPorts, nil)
	return nd, nn, nil
}

func reportMeta() report.Meta {
	host, _ := os.Hostname()
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return report.Meta{Host: host, User: name}
}

func historyPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "SpyCam", "activity-history.jsonl")
}

// buildReport builds a work-verifier report from the current activity
// snapshot. If reset is true, the accumulation window is reset afterwards.
func buildReport(reset bool) report.Report {
	var usage []activity.Usage
	since := time.Now()
	if tracker != nil {
		usage, since = tracker.Snapshot()
	}
	r := report.Build(usage, since, time.Now(), reportMeta())
	if reset && tracker != nil {
		tracker.Reset()
	}
	return r
}

// serveDashboard serves the bundled scanner dashboard (same-origin) with the
// agent token injected, so the page can call the authenticated endpoints
// without the operator pasting a token or dealing with CORS. Served only on
// localhost by the agent.
func serveDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}
	b, err := assetsFS.ReadFile("ui/dashboard.html")
	if err != nil {
		http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
		return
	}
	tok, _ := json.Marshal(getToken())
	inject := "<head>\n<script>window.AGENT_TOKEN=" + string(tok) + ";window.AGENT_BASE=\"\";</script>"
	html := strings.Replace(string(b), "<head>", inject, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// registerAgentRoutes installs all agent HTTP endpoints on mux. Only /health
// and the localhost dashboard are unauthenticated; the data endpoints
// require the bearer token.
func registerAgentRoutes(mux *http.ServeMux) {
	// Bundled dashboard (localhost, token injected).
	mux.HandleFunc("/", serveDashboard)
	mux.HandleFunc("/dashboard", serveDashboard)

	// Liveness — unauthenticated by design.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if preflight(w, r) {
			return
		}
		writeJSON(w, map[string]any{
			"ok":       server != nil,
			"os":       osName(),
			"time":     time.Now().Format(time.RFC3339),
			"origin":   getAllowOrigin(),
			"site_url": getSiteURL(),
			"features": func() map[string]any {
				capOK, capMsg := activity.TitleCapability()
				return map[string]any{
					"active_scan_enabled":  getRemoteConfig().ActiveScanConsent,
					"activity_enabled":     getRemoteConfig().ActivityConsent,
					"title_capture_ok":     capOK,
					"title_capture_detail": capMsg,
				}
			}(),
		})
	})

	mux.HandleFunc("/networks", authWrap(func(w http.ResponseWriter, r *http.Request) {
		if preflight(w, r) {
			return
		}
		writeJSON(w, map[string]any{
			"networks": toNetscanNetworks(collectLanNetworks()),
			"os":       osName(),
			"at":       time.Now().Format(time.RFC3339),
		})
	}))

	// Enriched device scan. ?active=1 additionally runs an opt-in TCP sweep
	// (only effective if active scanning is enabled in config).
	mux.HandleFunc("/scan", authWrap(func(w http.ResponseWriter, r *http.Request) {
		if preflight(w, r) {
			return
		}
		active := r.URL.Query().Get("active") == "1"
		devs, nets, err := discover(active)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"devices":   devs,
			"networks":  nets,
			"os":        osName(),
			"at":        time.Now().Format(time.RFC3339),
			"active":    active && getRemoteConfig().ActiveScanConsent,
			"site_url":  getSiteURL(),
			"origin":    getAllowOrigin(),
			"agent_url": fmt.Sprintf("http://%s:%d", host, port),
		})
	}))

	// Camera-focused view: enriched scan filtered to likely cameras.
	mux.HandleFunc("/cameras", authWrap(func(w http.ResponseWriter, r *http.Request) {
		if preflight(w, r) {
			return
		}
		active := r.URL.Query().Get("active") == "1"
		devs, _, err := discover(active)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"cameras": netscan.Cameras(devs),
			"os":      osName(),
			"at":      time.Now().Format(time.RFC3339),
			"note":    "Heuristic (vendor OUI, open camera ports, hostname). Verify before acting.",
		})
	}))

	// Current activity snapshot (disclosed tracking).
	mux.HandleFunc("/activity", authWrap(func(w http.ResponseWriter, r *http.Request) {
		if preflight(w, r) {
			return
		}
		var usage []activity.Usage
		since := time.Now()
		if tracker != nil {
			usage, since = tracker.Snapshot()
		}
		writeJSON(w, map[string]any{
			"enabled":   getRemoteConfig().ActivityConsent,
			"disclosed": true,
			"since":     since.Format(time.RFC3339),
			"usage":     usage,
		})
	}))

	// Consent control. Disabling (opt-out) is allowed remotely; enabling is
	// NOT, because turning on monitoring must be an on-device, user-visible
	// action — never silently flipped on by the remote site.
	mux.HandleFunc("/activity/consent", authWrap(func(w http.ResponseWriter, r *http.Request) {
		if preflight(w, r) {
			return
		}
		enable := r.URL.Query().Get("enable") == "1"
		if enable {
			http.Error(w, "enable activity tracking from the desktop agent window (on-device consent required)", http.StatusForbidden)
			return
		}
		setTrackingConsent(false)
		writeJSON(w, map[string]any{"enabled": false})
	}))

	// Build a work-verifier report. ?reset=1 clears the window after.
	mux.HandleFunc("/report", authWrap(func(w http.ResponseWriter, r *http.Request) {
		if preflight(w, r) {
			return
		}
		reset := r.URL.Query().Get("reset") == "1"
		rep := buildReport(reset)
		if hp := historyPath(); hp != "" {
			if err := (report.History{Path: hp}).Append(rep); err != nil {
				logf("history append failed: %v", err)
			}
		}
		b, err := rep.JSON()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))

	mux.HandleFunc("/report/history", authWrap(func(w http.ResponseWriter, r *http.Request) {
		if preflight(w, r) {
			return
		}
		n := 0
		if v := r.URL.Query().Get("n"); v != "" {
			n, _ = strconv.Atoi(v)
		}
		reps, err := (report.History{Path: historyPath()}).Load(n)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"reports": reps})
	}))

	// Export current report as csv or json (download).
	mux.HandleFunc("/export", authWrap(func(w http.ResponseWriter, r *http.Request) {
		if preflight(w, r) {
			return
		}
		rep := buildReport(false)
		switch r.URL.Query().Get("format") {
		case "csv":
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=\"work-report.csv\"")
			if err := rep.WriteCSV(w); err != nil {
				logf("csv export failed: %v", err)
			}
		default:
			b, err := rep.JSON()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=\"work-report.json\"")
			_, _ = w.Write(b)
		}
	}))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
