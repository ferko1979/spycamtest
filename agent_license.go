package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"spycam-tray-agent/internal/license"
)

// appVersion is reported to the license server.
const appVersion = "1.0.0"

// licenseCheckInterval is how often the agent re-verifies while running.
const licenseCheckInterval = 30 * time.Minute

// licenseGraceWindow is how long the last-known entitlement is retained when
// the license server is unreachable, before falling back to base features.
const licenseGraceWindow = 24 * time.Hour

// licMgr is the entitlement manager. nil until initLicensing runs.
var licMgr *license.Manager

// baseFeatures are available without any valid license (free tier): passive
// discovery and the local dashboard. Everything else is gated by a code.
func baseFeatures() []string { return []string{license.FeatureScan} }

// ensureDeviceID generates and persists a stable per-install device id.
func ensureDeviceID() {
	cfg := getRemoteConfig()
	if cfg.DeviceID != "" {
		return
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		logf("device id generation failed: %v", err)
		return
	}
	cfg.DeviceID = hex.EncodeToString(b)
	if err := saveRemoteConfig(cfg); err != nil {
		logf("device id save failed: %v", err)
	}
	applyRemoteConfig(cfg)
}

// licenseClient builds a verification client from current config.
func licenseClient() license.Client {
	cfg := getRemoteConfig()
	return license.Client{
		ServerURL:    cfg.LicenseServerURL,
		DeviceID:     cfg.DeviceID,
		AppVersion:   appVersion,
		PinnedPubKey: cfg.LicensePublicKey,
	}
}

// initLicensing creates the manager, verifies once at startup, and starts the
// periodic (every 30 min) re-verification loop.
func initLicensing() {
	ensureDeviceID()
	licMgr = license.NewManager(licenseClient(), baseFeatures(), licenseGraceWindow)
	licMgr.SetCodes(getRemoteConfig().LicenseCodes)

	// Startup verification (non-blocking so the UI/tray come up promptly).
	go refreshLicense()

	go func() {
		t := time.NewTicker(licenseCheckInterval)
		defer t.Stop()
		for range t.C {
			refreshLicense()
		}
	}()
}

// refreshLicense re-reads codes from config (they may have changed) and
// verifies against the server.
func refreshLicense() {
	if licMgr == nil {
		return
	}
	licMgr.SetCodes(getRemoteConfig().LicenseCodes)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Rebuild the client each run so server URL / pinned key edits take effect.
	licMgr.SetVerifier(licenseClient())
	licMgr.Refresh(ctx)
	if ent := licMgr.Snapshot(); ent.Degraded {
		logf("license: running on base features (degraded); last error: %s", ent.LastError)
	}
}

// licensed reports whether a feature is currently entitled. If licensing is
// not initialized yet, only base features are allowed.
func licensed(feature string) bool {
	if licMgr == nil {
		return license.Has(baseFeatures(), feature)
	}
	return licMgr.Has(feature)
}

// requireFeature wraps a handler, returning 402 when the feature is not
// entitled under the current license.
func requireFeature(feature string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next(w, r)
			return
		}
		if !licensed(feature) {
			cors(w, getAllowOrigin())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "feature not licensed",
				"feature": feature,
				"hint":    "enter a license code that includes this service in the agent window",
			})
			return
		}
		next(w, r)
	}
}

// licenseInfo returns the current entitlement plus the configured server and
// device id for display (codes themselves are not echoed raw here).
func licenseInfo() map[string]any {
	cfg := getRemoteConfig()
	var ent any
	if licMgr != nil {
		ent = licMgr.Snapshot()
	}
	return map[string]any{
		"server_url":  cfg.LicenseServerURL,
		"device_id":   cfg.DeviceID,
		"code_count":  len(cfg.LicenseCodes),
		"pinned_key":  cfg.LicensePublicKey != "",
		"entitlement": ent,
	}
}

// gated wraps a handler with both token auth and a feature-entitlement check.
func gated(feature string, h http.HandlerFunc) http.HandlerFunc {
	return authWrap(requireFeature(feature, h))
}

// setLicenseConfig persists server URL, codes and pinned key, then refreshes.
func setLicenseConfig(serverURL string, codes []string, pinnedKey string) {
	cfg := getRemoteConfig()
	cfg.LicenseServerURL = strings.TrimSpace(serverURL)
	cfg.LicensePublicKey = strings.TrimSpace(pinnedKey)
	cleaned := make([]string, 0, len(codes))
	for _, c := range codes {
		if c = strings.TrimSpace(c); c != "" {
			cleaned = append(cleaned, c)
		}
	}
	cfg.LicenseCodes = cleaned
	_ = saveRemoteConfig(cfg)
	applyRemoteConfig(cfg)
	go refreshLicense()
}
