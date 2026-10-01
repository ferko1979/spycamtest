package netscan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Fingerprint holds evidence gathered by actively probing a device for
// camera signatures. All fields are best-effort.
type Fingerprint struct {
	RTSP       bool   `json:"rtsp,omitempty"`        // RTSP OPTIONS answered
	RTSPServer string `json:"rtsp_server,omitempty"` // RTSP Server header
	HTTPServer string `json:"http_server,omitempty"` // HTTP Server header
	Realm      string `json:"realm,omitempty"`       // WWW-Authenticate realm
	ONVIF      bool   `json:"onvif,omitempty"`       // ONVIF service path responded
}

// Any reports whether the fingerprint found any camera-positive signal.
func (f Fingerprint) Any() bool {
	return f.RTSP || f.ONVIF || f.HTTPServer != "" || f.RTSPServer != ""
}

// FingerprintDevice actively probes ip for camera signatures: an RTSP
// OPTIONS request on 554 and an HTTP banner / ONVIF path check on 80.
//
// This sends data to the target and must only be called for devices on a
// network the user is authorized to scan, gated behind active-scan consent.
// All errors are swallowed; absence of signal just yields a zero value.
func FingerprintDevice(ctx context.Context, ip string, timeout time.Duration) Fingerprint {
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	var fp Fingerprint

	if raw, ok := rtspOptions(ctx, ip, 554, timeout); ok {
		fp.RTSP = true
		fp.RTSPServer = headerValue(raw, "Server")
	}
	if server, realm, ok := httpBanner(ctx, ip, 80, timeout); ok {
		fp.HTTPServer = server
		fp.Realm = realm
	}
	if onvifResponds(ctx, ip, 80, timeout) {
		fp.ONVIF = true
	}
	return fp
}

// ApplyFingerprints actively fingerprints devices that already look
// camera-ish (flagged likely, or with an open camera port) and folds the
// evidence into each device, confirming LikelyCamera on a positive
// RTSP/ONVIF result. Active — gate behind active-scan consent.
func ApplyFingerprints(ctx context.Context, devs []Device, timeout time.Duration) {
	for i := range devs {
		d := &devs[i]
		if !d.LikelyCamera && len(d.OpenPorts) == 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		fp := FingerprintDevice(ctx, d.IP, timeout)
		if !fp.Any() {
			continue
		}
		d.Fingerprint = &fp
		if fp.RTSP {
			d.LikelyCamera = true
			d.CameraReasons = append(d.CameraReasons, "RTSP OPTIONS responded (confirmed stream endpoint)")
		}
		if fp.ONVIF {
			d.LikelyCamera = true
			d.CameraReasons = append(d.CameraReasons, "ONVIF device service present")
		}
		if fp.RTSPServer != "" {
			d.CameraReasons = append(d.CameraReasons, "RTSP server: "+fp.RTSPServer)
		}
		if fp.Realm != "" {
			d.CameraReasons = append(d.CameraReasons, "HTTP auth realm: "+fp.Realm)
		}
	}
}

// rtspOptions sends an RTSP OPTIONS request and returns the raw response if
// the peer speaks RTSP.
func rtspOptions(ctx context.Context, ip string, portNum int, timeout time.Duration) (string, bool) {
	conn, err := dial(ctx, ip, portNum, timeout)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: spycam-agent\r\n\r\n", ip, portNum)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", false
	}
	raw := readSome(conn, 2048)
	if strings.Contains(raw, "RTSP/") {
		return raw, true
	}
	return "", false
}

// httpBanner does a minimal HTTP/1.0 GET / and returns the Server header and
// any WWW-Authenticate realm.
func httpBanner(ctx context.Context, ip string, portNum int, timeout time.Duration) (server, realm string, ok bool) {
	conn, err := dial(ctx, ip, portNum, timeout)
	if err != nil {
		return "", "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: spycam-agent\r\n\r\n", ip)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", "", false
	}
	raw := readSome(conn, 4096)
	if !strings.HasPrefix(raw, "HTTP/") {
		return "", "", false
	}
	server = headerValue(raw, "Server")
	if wa := headerValue(raw, "WWW-Authenticate"); wa != "" {
		realm = extractRealm(wa)
	}
	return server, realm, true
}

// onvifResponds checks whether the ONVIF device-service path exists (any
// non-404 HTTP status, including 401, indicates the endpoint is present).
func onvifResponds(ctx context.Context, ip string, portNum int, timeout time.Duration) bool {
	conn, err := dial(ctx, ip, portNum, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET /onvif/device_service HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}
	raw := readSome(conn, 512)
	status := statusCode(raw)
	return status != 0 && status != 404
}

func dial(ctx context.Context, ip string, portNum int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, portNum))
}

func readSome(conn net.Conn, max int) string {
	buf := make([]byte, max)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// headerValue extracts a header value (case-insensitive) from a raw HTTP/RTSP
// response. Returns "" if absent.
func headerValue(raw, name string) string {
	sc := bufio.NewScanner(strings.NewReader(raw))
	lname := strings.ToLower(name) + ":"
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of headers
		}
		if strings.HasPrefix(strings.ToLower(line), lname) {
			return strings.TrimSpace(line[len(lname):])
		}
	}
	return ""
}

func extractRealm(wwwAuth string) string {
	i := strings.Index(strings.ToLower(wwwAuth), "realm=")
	if i < 0 {
		return ""
	}
	v := wwwAuth[i+len("realm="):]
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"`)
	if j := strings.IndexAny(v, `",`); j >= 0 {
		v = v[:j]
	}
	return v
}

func statusCode(raw string) int {
	if !strings.HasPrefix(raw, "HTTP/") {
		return 0
	}
	parts := strings.SplitN(raw, " ", 3)
	if len(parts) < 2 {
		return 0
	}
	var code int
	_, err := fmt.Sscanf(parts[1], "%d", &code)
	if err != nil {
		return 0
	}
	return code
}
