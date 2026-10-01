package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/systray"
	"github.com/pkg/browser"
	webview "github.com/webview/webview_go"
)

// Must exist exactly:
// - assets/icon.ico
// - assets/icon.png
// - ui/index.html
//
//go:embed assets/icon.ico assets/icon.png ui/index.html ui/dashboard.html
var assetsFS embed.FS

type Device struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname,omitempty"`
}

type LanNetwork struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	CIDR      string `json:"cidr"`
	MAC       string `json:"mac,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
}

type RemoteConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	HTTPS       bool   `json:"https"`
	ScannerPath string `json:"scanner_path"`

	// Token is the bearer token required by the local agent API. It is
	// generated on first run (see ensureToken) and replaces the former
	// hard-coded admin password.
	Token string `json:"token,omitempty"`

	// ActivityConsent records that the user has consented to the disclosed
	// activity tracker (app/window-title/time). Default false: nothing is
	// tracked until the user turns it on in the agent window.
	ActivityConsent bool `json:"activity_consent"`

	// ActiveScanConsent enables the opt-in active TCP sweep of local
	// subnets. Default false: discovery is passive unless the user opts in.
	ActiveScanConsent bool `json:"active_scan_consent"`

	// SampleIntervalSec is how often the activity tracker samples the
	// foreground window (seconds). Default 5 if unset/invalid.
	SampleIntervalSec int `json:"sample_interval_sec,omitempty"`

	// IdleThresholdSec is how long with no input before samples count as
	// idle (seconds). Default 180 if unset/invalid.
	IdleThresholdSec int `json:"idle_threshold_sec,omitempty"`
}

// SampleInterval returns the configured sampling interval, with a default.
func (c RemoteConfig) SampleInterval() time.Duration {
	if c.SampleIntervalSec <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.SampleIntervalSec) * time.Second
}

// IdleThreshold returns the configured idle threshold, with a default.
func (c RemoteConfig) IdleThreshold() time.Duration {
	if c.IdleThresholdSec <= 0 {
		return 3 * time.Minute
	}
	return time.Duration(c.IdleThresholdSec) * time.Second
}

func (c RemoteConfig) Origin() string {
	scheme := "http"
	if c.HTTPS {
		scheme = "https"
	}
	host := strings.TrimSpace(c.Host)
	if host == "" {
		host = "spycamera.test"
	}

	// If host includes :port, strip it (port is stored separately)
	if h, p, ok := splitHostPortLoose(host); ok && p > 0 {
		host = h
		if c.Port <= 0 {
			c.Port = p
		}
	}

	// Include :port only if non-default for the scheme
	port := c.Port
	if port <= 0 {
		if c.HTTPS {
			port = 443
		} else {
			port = 80
		}
	}

	hostport := host
	if (c.HTTPS && port != 443) || (!c.HTTPS && port != 80) {
		hostport = fmt.Sprintf("%s:%d", host, port)
	}

	return scheme + "://" + hostport
}

func (c RemoteConfig) ScannerURL() string {
	p := c.ScannerPath
	if strings.TrimSpace(p) == "" {
		p = "/scanner"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(c.Origin(), "/") + p
}

var (
	// Local bind (agent)
	host string
	port int

	// Deprecated-ish flags: still accepted for initial defaults
	allowOriginFlag string
	siteURLFlag     string

	// Runtime remote settings (derived from RemoteConfig)
	cfgMu       sync.RWMutex
	remoteCfg   RemoteConfig
	allowOrigin string
	siteURL     string

	server   *http.Server
	listener net.Listener

	startupMenu *systray.MenuItem

	uiMu      sync.Mutex
	uiShowing bool
)

func main() {
	flag.StringVar(&host, "host", "127.0.0.1", "bind host")
	flag.IntVar(&port, "port", 8765, "bind port")
	flag.StringVar(&allowOriginFlag, "allow-origin", "http://spycamera.test", "allowed browser origin (CORS)")
	flag.StringVar(&siteURLFlag, "site-url", "http://spycamera.test/scanner", "scanner website URL")
	flag.Parse()

	// Load persisted remote config (or derive defaults from flags)
	cfg := loadRemoteConfigOrDefault(defaultRemoteFromFlags(allowOriginFlag, siteURLFlag))
	applyRemoteConfig(cfg)
	ensureToken()

	systray.Run(onReady, onExit)
}

func onReady() {
	// Tray icon (try preferred format; fallback to PNG always)
	if runtime.GOOS == "windows" {
		if b, err := assetsFS.ReadFile("assets/icon.ico"); err == nil && len(b) > 0 {
			systray.SetIcon(b)
		} else if b, err2 := assetsFS.ReadFile("assets/icon.png"); err2 == nil && len(b) > 0 {
			systray.SetIcon(b)
		} else {
			logf("tray icon missing: icoErr=%v pngErr=%v", err, err2)
		}
	} else {
		if b, err := assetsFS.ReadFile("assets/icon.png"); err == nil && len(b) > 0 {
			systray.SetIcon(b)
		} else {
			logf("tray icon missing: %v", err)
		}
	}

	systray.SetTitle("SpyCam Agent")
	systray.SetTooltip("SpyCam Agent running locally for network scan")

	// Start local API and the (consent-gated) activity tracker.
	if err := startAgent(); err != nil {
		logf("Failed to start agent: %v", err)
	}
	initIntegrations()

	// Menu items
	mOpenUI := systray.AddMenuItem("Open Agent Window", "Open the SpyCam Agent control window")
	mOpen := systray.AddMenuItem("Open Scanner Website", "Open the scanner page in your default browser")

	mHealth := systray.AddMenuItem(fmt.Sprintf("Agent: http://%s:%d", host, port), "Local agent endpoint")
	mHealth.Disable()

	systray.AddSeparator()

	// Visible, on-device control for activity tracking. Its checked state
	// mirrors consent, and the tray title also shows ON/OFF, so the person
	// on this machine can always see and stop tracking.
	mTracking := systray.AddMenuItemCheckbox("Activity tracking (app/title/time)", "Disclosed work-activity tracking. Visible while running; you can turn it off here.", getRemoteConfig().ActivityConsent)

	startupMenu = systray.AddMenuItemCheckbox("Run on startup", "Start SpyCam Agent when you log in", false)
	enabled, _ := startupIsEnabled()
	if enabled {
		startupMenu.Check()
	} else {
		startupMenu.Uncheck()
	}

	// Reflect current tracking state in the tray title/tooltip.
	updateTrayIndicator()

	mQuit := systray.AddMenuItem("Quit", "Stop agent and exit")

	go func() {
		for {
			select {
			case <-mOpenUI.ClickedCh:
				go showUiWindow()

			case <-mOpen.ClickedCh:
				_ = openURL(getSiteURL())

			case <-mTracking.ClickedCh:
				// Toggle disclosed activity tracking from the tray.
				if mTracking.Checked() {
					setTrackingConsent(false)
					mTracking.Uncheck()
				} else {
					setTrackingConsent(true)
					mTracking.Check()
				}

			case <-startupMenu.ClickedCh:
				if startupMenu.Checked() {
					_ = startupDisable()
					startupMenu.Uncheck()
				} else {
					_ = startupEnable()
					startupMenu.Check()
				}

			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func onExit() {
	stopIntegrations()
	_ = stopAgent()
}

func showUiWindow() {
	uiMu.Lock()
	if uiShowing {
		uiMu.Unlock()
		return
	}
	uiShowing = true
	uiMu.Unlock()

	defer func() {
		uiMu.Lock()
		uiShowing = false
		uiMu.Unlock()
	}()

	htmlTplBytes, err := assetsFS.ReadFile("ui/index.html")
	if err != nil {
		logf("UI read failed: %v (did you embed ui/index.html?)", err)
		return
	}

	logoBytes, errLogo := assetsFS.ReadFile("assets/icon.png")
	if errLogo != nil {
		logf("Logo read failed: %v (did you embed assets/icon.png?)", errLogo)
		logoBytes = nil
	}

	logoB64 := ""
	if len(logoBytes) > 0 {
		logoB64 = base64.StdEncoding.EncodeToString(logoBytes)
	}

	html := strings.ReplaceAll(string(htmlTplBytes), "{{LOGO_BASE64}}", logoB64)

	w := webview.New(false)
	defer w.Destroy()

	w.SetTitle("SpyCam Agent")
	w.SetSize(460, 520, webview.HintNone)

	// --- JS bindings used by ui/index.html ---
	_ = w.Bind("openScanner", func() {
		_ = openURL(getSiteURL())
	})

	_ = w.Bind("hideUi", func() {
		// closes only the UI window, keeps tray/agent running
		w.Terminate()
	})

	_ = w.Bind("quitApp", func() {
		_ = stopAgent()
		systray.Quit()
	})

	_ = w.Bind("startupEnabled", func() bool {
		enabled, _ := startupIsEnabled()
		return enabled
	})

	_ = w.Bind("setStartupEnabled", func(enable bool) {
		if enable {
			_ = startupEnable()
			if startupMenu != nil {
				startupMenu.Check()
			}
		} else {
			_ = startupDisable()
			if startupMenu != nil {
				startupMenu.Uncheck()
			}
		}
	})

	_ = w.Bind("agentEndpoint", func() string {
		return fmt.Sprintf("http://%s:%d", host, port)
	})

	_ = w.Bind("agentHealth", func() map[string]any {
		return map[string]any{
			"ok":   server != nil,
			"os":   runtime.GOOS,
			"time": time.Now().Format(time.RFC3339),
		}
	})

	_ = w.Bind("getConnectionConfig", func() map[string]any {
		cfg := getRemoteConfig()
		return map[string]any{
			"host":                cfg.Host,
			"port":                cfg.Port,
			"https":               cfg.HTTPS,
			"scanner_path":        cfg.ScannerPath,
			"origin":              cfg.Origin(),
			"scanner_url":         cfg.ScannerURL(),
			"config_path":         mustConfigPath(),
			"sample_interval_sec": int(cfg.SampleInterval() / time.Second),
			"idle_threshold_sec":  int(cfg.IdleThreshold() / time.Second),
			"dashboard_url":       fmt.Sprintf("http://%s:%d/dashboard", host, port),
		}
	})

	_ = w.Bind("saveConnectionConfig", func(newHost string, newPort int, https bool) (map[string]any, error) {
		newHost = strings.TrimSpace(newHost)
		if newHost == "" {
			return nil, errors.New("host/address is required")
		}
		// strip scheme if user pasted it
		newHost = strings.TrimPrefix(newHost, "http://")
		newHost = strings.TrimPrefix(newHost, "https://")
		newHost = strings.TrimRight(newHost, "/")

		// allow "host:port" pasted into host field
		if h, p, ok := splitHostPortLoose(newHost); ok && p > 0 {
			newHost = h
			if newPort <= 0 {
				newPort = p
			}
		}

		if newPort <= 0 || newPort > 65535 {
			return nil, errors.New("port must be between 1 and 65535")
		}

		cfg := getRemoteConfig()
		cfg.Host = newHost
		cfg.Port = newPort
		cfg.HTTPS = https
		if strings.TrimSpace(cfg.ScannerPath) == "" {
			cfg.ScannerPath = "/scanner"
		}

		if err := saveRemoteConfig(cfg); err != nil {
			return nil, err
		}
		applyRemoteConfig(cfg)

		return map[string]any{
			"ok":          true,
			"origin":      cfg.Origin(),
			"scanner_url": cfg.ScannerURL(),
		}, nil
	})

	// Agent API token, so the operator can configure the scanner site.
	_ = w.Bind("getAgentToken", func() string {
		return getToken()
	})

	// Current activity-tracking state for the window UI.
	_ = w.Bind("getActivityState", func() map[string]any {
		var count int
		if tracker != nil {
			us, _ := tracker.Snapshot()
			count = len(us)
		}
		return map[string]any{
			"consent":             getRemoteConfig().ActivityConsent,
			"active_scan_consent": getRemoteConfig().ActiveScanConsent,
			"entries":             count,
		}
	})

	// Consent toggle for activity tracking. This is the on-device, informed
	// consent action; it flips the visible tray indicator too.
	_ = w.Bind("setActivityConsent", func(enable bool) map[string]any {
		setTrackingConsent(enable)
		return map[string]any{"consent": getRemoteConfig().ActivityConsent}
	})

	// Opt-in toggle for the active (packet-sending) network sweep.
	_ = w.Bind("setActiveScanConsent", func(enable bool) map[string]any {
		cfg := getRemoteConfig()
		cfg.ActiveScanConsent = enable
		_ = saveRemoteConfig(cfg)
		applyRemoteConfig(cfg)
		return map[string]any{"active_scan_consent": getRemoteConfig().ActiveScanConsent}
	})

	// Window-title capability + OS permission remediation.
	_ = w.Bind("getPermissionStatus", func() map[string]any {
		ok, detail := permissionStatus()
		return map[string]any{"ok": ok, "detail": detail}
	})

	_ = w.Bind("openPermissionSettings", func() {
		_ = openActivityPermission()
	})

	// Editable sampling settings (interval + idle threshold).
	_ = w.Bind("saveActivitySettings", func(intervalSec, idleSec int) (map[string]any, error) {
		if err := saveActivitySettings(intervalSec, idleSec); err != nil {
			return nil, err
		}
		cfg := getRemoteConfig()
		return map[string]any{
			"sample_interval_sec": cfg.SampleIntervalSec,
			"idle_threshold_sec":  cfg.IdleThresholdSec,
		}, nil
	})

	// Open the bundled local scanner dashboard in the browser.
	_ = w.Bind("openDashboard", func() {
		_ = openURL(fmt.Sprintf("http://%s:%d/dashboard", host, port))
	})

	// Live snapshot of the user's own tracked activity, so the monitored
	// person can see exactly what is recorded about them.
	_ = w.Bind("getMyActivity", func() []map[string]any {
		out := []map[string]any{}
		if tracker != nil {
			us, _ := tracker.Snapshot()
			for _, u := range us {
				out = append(out, map[string]any{
					"app":     u.App,
					"title":   u.Title,
					"seconds": u.Seconds,
				})
			}
		}
		return out
	})
	// --- end bindings ---

	w.SetHtml(html)
	w.Run()
}

func startAgent() error {
	addr := fmt.Sprintf("%s:%d", host, port)

	mux := http.NewServeMux()

	// All agent endpoints (health, networks, enriched scan, cameras,
	// activity, report, export) are registered here. Everything but /health
	// is behind bearer-token auth. See agent_integrations.go.
	registerAgentRoutes(mux)

	var err error
	listener, err = net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	server = &http.Server{Addr: addr, Handler: mux}
	go func() { _ = server.Serve(listener) }()

	return nil
}

func stopAgent() error {
	if server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = server.Shutdown(ctx)
	server = nil

	if listener != nil {
		_ = listener.Close()
		listener = nil
	}
	return nil
}

func cors(w http.ResponseWriter, allowOrigin string) {
	w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	// Authorization / X-Agent-Token are needed so the scanner site can send
	// the agent's bearer token on cross-origin requests.
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Agent-Token")
}

func openURL(url string) error {
	// Try pkg/browser first
	if err := browser.OpenURL(url); err == nil {
		return nil
	}

	// Fallbacks
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func scanNeighbors() ([]Device, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("arp", "-a").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("arp -a failed: %v", err)
		}
		return parseWindowsArp(string(out)), nil
	default:
		out, _ := exec.Command("sh", "-lc", "ip neigh 2>/dev/null || arp -a 2>/dev/null || true").CombinedOutput()
		return parseUnixNeighbors(string(out)), nil
	}
}

func parseWindowsArp(raw string) []Device {
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	seen := map[string]bool{}
	var devs []Device

	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		ip := f[0]
		mac := strings.ToLower(strings.ReplaceAll(f[1], "-", ":"))
		if !looksLikeIPv4(ip) || !looksLikeMAC(mac) {
			continue
		}
		key := ip + "|" + mac
		if seen[key] {
			continue
		}
		seen[key] = true
		devs = append(devs, Device{IP: ip, MAC: mac})
	}

	return devs
}

func parseUnixNeighbors(raw string) []Device {
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	seen := map[string]bool{}
	var devs []Device

	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}

		if strings.Contains(ln, "lladdr") {
			f := strings.Fields(ln)
			if len(f) < 5 {
				continue
			}
			ip := f[0]
			mac := ""
			for i := 0; i < len(f); i++ {
				if f[i] == "lladdr" && i+1 < len(f) {
					mac = strings.ToLower(f[i+1])
					break
				}
			}
			if !looksLikeIPv4(ip) || !looksLikeMAC(mac) {
				continue
			}
			key := ip + "|" + mac
			if seen[key] {
				continue
			}
			seen[key] = true
			devs = append(devs, Device{IP: ip, MAC: mac})
			continue
		}

		if strings.Contains(ln, "(") && strings.Contains(ln, ")") && strings.Contains(ln, " at ") {
			ip := between(ln, "(", ")")
			parts := strings.SplitN(ln, " at ", 2)
			if len(parts) != 2 {
				continue
			}
			m := strings.Fields(parts[1])
			if len(m) == 0 {
				continue
			}
			mac := strings.ToLower(m[0])
			if !looksLikeIPv4(ip) || !looksLikeMAC(mac) {
				continue
			}
			key := ip + "|" + mac
			if seen[key] {
				continue
			}
			seen[key] = true
			devs = append(devs, Device{IP: ip, MAC: mac})
		}
	}

	return devs
}

func collectLanNetworks() []LanNetwork {
	ifaces, _ := net.Interfaces()
	gw := defaultGatewayIPv4()

	var nets []LanNetwork
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP == nil {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}

			nets = append(nets, LanNetwork{
				Interface: iface.Name,
				IP:        ip4.String(),
				CIDR:      ipnet.String(),
				MAC:       iface.HardwareAddr.String(),
				Gateway:   gw,
			})
			break
		}
	}
	return nets
}

func defaultGatewayIPv4() string {
	switch runtime.GOOS {
	case "windows":
		out, _ := exec.Command("cmd", "/C", "route", "print", "-4").CombinedOutput()
		return parseWindowsDefaultGateway(string(out))
	case "darwin":
		out, _ := exec.Command("sh", "-lc", "route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}'").CombinedOutput()
		return strings.TrimSpace(string(out))
	default:
		out, _ := exec.Command("sh", "-lc", "ip route show default 2>/dev/null | awk '{print $3; exit}'").CombinedOutput()
		gw := strings.TrimSpace(string(out))
		if gw != "" {
			return gw
		}
		out2, _ := exec.Command("sh", "-lc", "route -n 2>/dev/null | awk '$1==\"0.0.0.0\"{print $2; exit}'").CombinedOutput()
		return strings.TrimSpace(string(out2))
	}
}

func parseWindowsDefaultGateway(raw string) string {
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	for _, ln := range lines {
		f := strings.Fields(strings.TrimSpace(ln))
		// Typical: 0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.123  25
		if len(f) >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" && looksLikeIPv4(f[2]) {
			return f[2]
		}
	}
	return ""
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	j := strings.Index(s, b)
	if i == -1 || j == -1 || j <= i {
		return ""
	}
	return s[i+len(a) : j]
}

func looksLikeIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && strings.Count(s, ".") == 3
}

func looksLikeMAC(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(strings.ReplaceAll(s, "-", ":"), ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
	}
	return true
}

// Remote config persistence
func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "SpyCam", "config.json"), nil
}

func mustConfigPath() string {
	p, err := configPath()
	if err != nil {
		return ""
	}
	return p
}

func loadRemoteConfigOrDefault(def RemoteConfig) RemoteConfig {
	p, err := configPath()
	if err != nil {
		return def
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return def
	}
	var cfg RemoteConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return def
	}
	// sanity defaults
	if strings.TrimSpace(cfg.Host) == "" {
		cfg.Host = def.Host
	}
	if cfg.Port <= 0 {
		cfg.Port = def.Port
	}
	if strings.TrimSpace(cfg.ScannerPath) == "" {
		cfg.ScannerPath = def.ScannerPath
	}
	return cfg
}

func saveRemoteConfig(cfg RemoteConfig) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(p), 0755)

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	tmp := p + ".tmp"
	// 0600 on unix; on windows it's ignored but OK
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	_ = os.Remove(p) // windows rename safety
	return os.Rename(tmp, p)
}

func applyRemoteConfig(cfg RemoteConfig) {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	remoteCfg = cfg
	allowOrigin = cfg.Origin()
	siteURL = cfg.ScannerURL()
}

func getRemoteConfig() RemoteConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return remoteCfg
}

func getAllowOrigin() string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return allowOrigin
}

func getSiteURL() string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return siteURL
}

// Derive default remote config from the old flags (so your existing CLI behavior remains sensible)
func defaultRemoteFromFlags(allowOriginStr, siteURLStr string) RemoteConfig {
	cfg := RemoteConfig{
		Host:        "spycamera.test",
		Port:        80,
		HTTPS:       false,
		ScannerPath: "/scanner",
	}

	// Prefer parsing site-url for path
	if u, err := url.Parse(siteURLStr); err == nil && u.Host != "" {
		cfg.HTTPS = strings.EqualFold(u.Scheme, "https")
		cfg.Host = u.Hostname()
		if p := u.Port(); p != "" {
			if n, _ := strconv.Atoi(p); n > 0 {
				cfg.Port = n
			}
		} else {
			if cfg.HTTPS {
				cfg.Port = 443
			} else {
				cfg.Port = 80
			}
		}
		if u.Path != "" {
			cfg.ScannerPath = u.Path
		}
	}

	// allow-origin can override scheme/host/port if it parses cleanly
	if u, err := url.Parse(allowOriginStr); err == nil && u.Host != "" {
		cfg.HTTPS = strings.EqualFold(u.Scheme, "https")
		cfg.Host = u.Hostname()
		if p := u.Port(); p != "" {
			if n, _ := strconv.Atoi(p); n > 0 {
				cfg.Port = n
			}
		} else {
			if cfg.HTTPS {
				cfg.Port = 443
			} else {
				cfg.Port = 80
			}
		}
	}

	return cfg
}

func splitHostPortLoose(s string) (string, int, bool) {
	// Accept "example.com:8080" or "192.168.0.5:8080"
	// (Does not attempt IPv6 parsing.)
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", 0, false
	}
	hostPart := s[:i]
	portPart := s[i+1:]
	n, err := strconv.Atoi(portPart)
	if err != nil || n <= 0 || n > 65535 {
		return "", 0, false
	}
	return hostPart, n, true
}

// Writes to: %APPDATA%\SpyCam\spycam-agent.log  (or OS equivalent)
func logf(format string, args ...any) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return
	}
	p := filepath.Join(dir, "SpyCam", "spycam-agent.log")
	_ = os.MkdirAll(filepath.Dir(p), 0755)

	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	_, _ = fmt.Fprintf(f, time.Now().Format(time.RFC3339)+" "+format+"\n", args...)
}

// --- existing startup helpers are assumed to exist in your project ---
// startupIsEnabled() (bool, error)
// startupEnable() error
// startupDisable() error
