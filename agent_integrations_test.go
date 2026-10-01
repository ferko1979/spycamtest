package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// setupTestServer wires the real agent routes with a known token.
func setupTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	const tok = "test-token-123"
	applyRemoteConfig(RemoteConfig{
		Host: "example.test", Port: 80, ScannerPath: "/scanner", Token: tok,
	})
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
