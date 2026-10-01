package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"spycam-tray-agent/internal/license"
	"spycam-tray-agent/internal/report"
)

// allFeatVerifier grants every feature for any code.
type allFeatVerifier struct{ valid bool }

func (a allFeatVerifier) VerifyCode(_ context.Context, code string) (license.Claims, error) {
	if !a.valid {
		return license.Claims{Code: code, Valid: false, Reason: "test"}, nil
	}
	return license.Claims{Code: code, Valid: true, Plan: "test", Features: license.AllFeatures(), IssuedAt: time.Now()}, nil
}

// grantAllFeatures installs a manager entitling every feature.
func grantAllFeatures() {
	licMgr = license.NewManager(allFeatVerifier{valid: true}, []string{license.FeatureScan}, time.Hour)
	licMgr.SetCodes([]string{"TEST"})
	licMgr.Refresh(context.Background())
}

// grantBaseOnly installs a manager with no valid codes (base features only).
func grantBaseOnly() {
	licMgr = license.NewManager(allFeatVerifier{valid: false}, []string{license.FeatureScan}, time.Hour)
	licMgr.SetCodes([]string{"TEST"})
	licMgr.Refresh(context.Background())
}

// setupTestServer wires the real agent routes with a known token.
func setupTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	const tok = "test-token-123"
	applyRemoteConfig(RemoteConfig{
		Host: "example.test", Port: 80, ScannerPath: "/scanner", Token: tok,
	})
	grantAllFeatures()
	mux := http.NewServeMux()
	registerAgentRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, tok
}

func get(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return res
}

func TestHealthNoAuth(t *testing.T) {
	srv, _ := setupTestServer(t)
	res := get(t, srv.URL+"/health", "")
	if res.StatusCode != 200 {
		t.Fatalf("/health status = %d, want 200", res.StatusCode)
	}
	res.Body.Close()
}

func TestScanRequiresToken(t *testing.T) {
	srv, tok := setupTestServer(t)

	res := get(t, srv.URL+"/scan", "")
	if res.StatusCode != 401 {
		t.Errorf("/scan without token = %d, want 401", res.StatusCode)
	}
	res.Body.Close()

	res = get(t, srv.URL+"/scan", tok)
	if res.StatusCode != 200 {
		t.Errorf("/scan with token = %d, want 200", res.StatusCode)
	}
	res.Body.Close()
}

func TestActivityConsentCannotEnableRemotely(t *testing.T) {
	srv, tok := setupTestServer(t)
	res := get(t, srv.URL+"/activity/consent?enable=1", tok)
	if res.StatusCode != 403 {
		t.Errorf("remote enable = %d, want 403 (on-device only)", res.StatusCode)
	}
	res.Body.Close()
}

func TestFeatureGating(t *testing.T) {
	srv, tok := setupTestServer(t) // grants all features
	// Downgrade to base-only (unlicensed).
	grantBaseOnly()

	// Base feature still works.
	res := get(t, srv.URL+"/scan", tok)
	if res.StatusCode != 200 {
		t.Errorf("/scan (base) = %d, want 200", res.StatusCode)
	}
	res.Body.Close()

	// Gated features are 402 Payment Required.
	for _, p := range []string{"/cameras", "/activity", "/report"} {
		res := get(t, srv.URL+p, tok)
		if res.StatusCode != http.StatusPaymentRequired {
			t.Errorf("%s unlicensed = %d, want 402", p, res.StatusCode)
		}
		res.Body.Close()
	}

	// Re-grant: now allowed.
	grantAllFeatures()
	res = get(t, srv.URL+"/cameras", tok)
	if res.StatusCode != 200 {
		t.Errorf("/cameras licensed = %d, want 200", res.StatusCode)
	}
	res.Body.Close()
}

func TestBaselineEndpoint(t *testing.T) {
	srv, tok := setupTestServer(t)
	res := get(t, srv.URL+"/baseline", tok)
	if res.StatusCode != 200 {
		t.Fatalf("/baseline status = %d, want 200", res.StatusCode)
	}
	res.Body.Close()
}

func TestReportSignedWhenSeedPresent(t *testing.T) {
	// setupTestServer sets a config without a seed; add one and verify the
	// report carries a valid signature.
	srv, tok := setupTestServer(t)
	seed, _ := report.GenerateSeed()
	cfg := getRemoteConfig()
	cfg.SigningSeed = seed
	applyRemoteConfig(cfg)

	res := get(t, srv.URL+"/report", tok)
	if res.StatusCode != 200 {
		t.Fatalf("/report status = %d", res.StatusCode)
	}
	var body struct {
		Signature *struct {
			Algo string `json:"algo"`
		} `json:"signature"`
	}
	_ = json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if body.Signature == nil || body.Signature.Algo != "ed25519" {
		t.Errorf("report should be signed, got %+v", body.Signature)
	}
}

func TestDashboardInjectsToken(t *testing.T) {
	srv, tok := setupTestServer(t)
	res := get(t, srv.URL+"/dashboard", "")
	if res.StatusCode != 200 {
		t.Fatalf("/dashboard status = %d, want 200", res.StatusCode)
	}
	buf := make([]byte, 4096)
	n, _ := res.Body.Read(buf)
	res.Body.Close()
	head := string(buf[:n])
	if !strings.Contains(head, "window.AGENT_TOKEN=") || !strings.Contains(head, tok) {
		t.Errorf("dashboard did not inject token; head=%q", head)
	}
}
