package netscan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeRTSP starts a TCP listener that answers one request with an RTSP
// response, and returns its port.
func fakeRTSP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: FakeCam/1.0\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"))
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestRTSPOptions(t *testing.T) {
	port := fakeRTSP(t)
	raw, ok := rtspOptions(context.Background(), "127.0.0.1", port, time.Second)
	if !ok {
		t.Fatal("expected RTSP detection")
	}
	if got := headerValue(raw, "Server"); got != "FakeCam/1.0" {
		t.Errorf("RTSP Server header = %q", got)
	}
}

func TestRTSPOptionsNonRTSP(t *testing.T) {
	// An HTTP server should not be detected as RTSP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	if _, ok := rtspOptions(context.Background(), host, port, time.Second); ok {
		t.Error("HTTP server should not be detected as RTSP")
	}
}

func TestHTTPBanner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Hikvision-Webs")
		w.Header().Set("WWW-Authenticate", `Digest realm="IP Camera", nonce="abc"`)
		w.WriteHeader(401)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	server, realm, ok := httpBanner(context.Background(), host, port, time.Second)
	if !ok {
		t.Fatal("expected HTTP banner")
	}
	if server != "Hikvision-Webs" {
		t.Errorf("Server = %q", server)
	}
	if realm != "IP Camera" {
		t.Errorf("realm = %q", realm)
	}
}

func TestExtractRealmAndStatus(t *testing.T) {
	if r := extractRealm(`Digest realm="My Cam", qop="auth"`); r != "My Cam" {
		t.Errorf("extractRealm = %q", r)
	}
	if c := statusCode("HTTP/1.0 401 Unauthorized\r\n"); c != 401 {
		t.Errorf("statusCode = %d", c)
	}
	if c := statusCode("not http"); c != 0 {
		t.Errorf("non-http statusCode = %d", c)
	}
}

func TestApplyFingerprintsConfirmsCamera(t *testing.T) {
	// Device with no camera-ish signal is skipped (no panic, no change).
	devs := []Device{{IP: "127.0.0.1", MAC: "aa:bb:cc:dd:ee:ff"}}
	ApplyFingerprints(context.Background(), devs, 200*time.Millisecond)
	if devs[0].Fingerprint != nil {
		t.Error("non-camera device should be skipped")
	}
}
