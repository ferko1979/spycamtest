package license

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AuditEntry records one admin action for traceability.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"` // issue | revoke | enable | delete
	Code   string    `json:"code"`
	Detail string    `json:"detail,omitempty"`
	OK     bool      `json:"ok"`
}

const auditRingMax = 500

// record appends an audit entry to the ring and the optional sink. Caller must
// NOT hold s.mu (it takes the lock itself).
func (s *Store) record(e AuditEntry) {
	s.mu.Lock()
	if e.Time.IsZero() {
		e.Time = s.now().UTC().Truncate(time.Second)
	}
	s.audit = append(s.audit, e)
	if len(s.audit) > auditRingMax {
		s.audit = s.audit[len(s.audit)-auditRingMax:]
	}
	hook := s.auditHook
	s.mu.Unlock()
	if hook != nil {
		hook(e)
	}
}

// AuditLog returns a copy of the recent admin-action entries (newest last).
func (s *Store) AuditLog() []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEntry(nil), s.audit...)
}

// IssueRequest creates (or overwrites) a license code. If Code is empty a
// random code is generated.
type IssueRequest struct {
	Code        string   `json:"code,omitempty"`
	Plan        string   `json:"plan"`
	Features    []string `json:"features"`
	MaxDevices  int      `json:"max_devices,omitempty"`
	ExpiresDays int      `json:"expires_days,omitempty"` // 0 = never expires
}

// AdminLicense is a License plus its code, for listing/issue responses.
type AdminLicense struct {
	Code string `json:"code"`
	License
}

// codeChars avoids ambiguous characters (0/O, 1/I).
const codeChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GenerateCode returns a grouped random code like "AB7K-9QF2-M4TX".
func GenerateCode() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	var sb strings.Builder
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(codeChars[int(v)%len(codeChars)])
	}
	return sb.String()
}

// Issue adds or replaces a license. Returns the stored AdminLicense.
func (s *Store) Issue(req IssueRequest) (AdminLicense, error) {
	if req.Plan == "" {
		return AdminLicense{}, errors.New("plan is required")
	}
	if len(req.Features) == 0 {
		return AdminLicense{}, errors.New("at least one feature is required")
	}
	lic := &License{
		Plan:       req.Plan,
		Features:   append([]string(nil), req.Features...),
		MaxDevices: req.MaxDevices,
	}
	if req.ExpiresDays > 0 {
		lic.Expires = s.now().UTC().Add(time.Duration(req.ExpiresDays) * 24 * time.Hour).Truncate(time.Second)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	code := strings.TrimSpace(req.Code)
	if code == "" {
		for {
			code = GenerateCode()
			if _, exists := s.licenses[code]; !exists {
				break
			}
		}
	}
	s.licenses[code] = lic
	if s.onChange != nil {
		s.onChange(s.licenses)
	}
	return AdminLicense{Code: code, License: *lic}, nil
}

// SetDisabled enables or disables a code. Returns an error if unknown.
func (s *Store) SetDisabled(code string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lic, ok := s.licenses[strings.TrimSpace(code)]
	if !ok {
		return errors.New("unknown code")
	}
	lic.Disabled = disabled
	if s.onChange != nil {
		s.onChange(s.licenses)
	}
	return nil
}

// Delete removes a code. Returns an error if unknown.
func (s *Store) Delete(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	code = strings.TrimSpace(code)
	if _, ok := s.licenses[code]; !ok {
		return errors.New("unknown code")
	}
	delete(s.licenses, code)
	if s.onChange != nil {
		s.onChange(s.licenses)
	}
	return nil
}

// List returns all licenses as AdminLicense entries.
func (s *Store) List() []AdminLicense {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AdminLicense, 0, len(s.licenses))
	for code, lic := range s.licenses {
		out = append(out, AdminLicense{Code: code, License: *lic})
	}
	return out
}

func (s *Store) adminAuthorized(r *http.Request) bool {
	s.mu.Lock()
	tok := s.adminToken
	s.mu.Unlock()
	if tok == "" {
		return false // admin disabled
	}
	h := r.Header.Get("Authorization")
	const p = "bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		got := strings.TrimSpace(h[len(p):])
		return subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1
	}
	return false
}

func (s *Store) registerAdminRoutes(mux *http.ServeMux) {
	admin := func(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !s.adminAuthorized(r) {
				http.Error(w, "admin unauthorized", http.StatusForbidden)
				return
			}
			fn(w, r)
		}
	}

	mux.HandleFunc("/api/admin/issue", admin(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req IssueRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		al, err := s.Issue(req)
		if err != nil {
			s.record(AuditEntry{Action: "issue", Detail: err.Error(), OK: false})
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.record(AuditEntry{Action: "issue", Code: al.Code, Detail: al.Plan, OK: true})
		writeJSON(w, al)
	}))

	codeAction := func(action string, apply func(code string) error) http.HandlerFunc {
		return admin(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var body struct {
				Code string `json:"code"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if err := apply(body.Code); err != nil {
				s.record(AuditEntry{Action: action, Code: body.Code, Detail: err.Error(), OK: false})
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			s.record(AuditEntry{Action: action, Code: body.Code, OK: true})
			writeJSON(w, map[string]any{"ok": true, "code": body.Code})
		})
	}

	mux.HandleFunc("/api/admin/revoke", codeAction("revoke", func(c string) error { return s.SetDisabled(c, true) }))
	mux.HandleFunc("/api/admin/enable", codeAction("enable", func(c string) error { return s.SetDisabled(c, false) }))
	mux.HandleFunc("/api/admin/delete", codeAction("delete", func(c string) error { return s.Delete(c) }))

	mux.HandleFunc("/api/admin/list", admin(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"licenses": s.List()})
	}))

	mux.HandleFunc("/api/admin/audit", admin(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"audit": s.AuditLog()})
	}))
}

// AdminClient talks to a license server's admin API.
type AdminClient struct {
	ServerURL string
	Token     string
	HTTP      *http.Client
}

func (c AdminClient) do(path string, body any, out any) error {
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	var rdr *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
	} else {
		rdr = strings.NewReader("")
	}
	req, err := http.NewRequest(http.MethodPost, trimSlash(c.ServerURL)+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Issue creates a code via the admin API.
func (c AdminClient) Issue(req IssueRequest) (AdminLicense, error) {
	var al AdminLicense
	err := c.do("/api/admin/issue", req, &al)
	return al, err
}

// Revoke/Enable/Delete act on a code.
func (c AdminClient) Revoke(code string) error {
	return c.do("/api/admin/revoke", map[string]string{"code": code}, nil)
}
func (c AdminClient) Enable(code string) error {
	return c.do("/api/admin/enable", map[string]string{"code": code}, nil)
}
func (c AdminClient) Delete(code string) error {
	return c.do("/api/admin/delete", map[string]string{"code": code}, nil)
}

// Audit returns the recent admin-action log via the admin API.
func (c AdminClient) Audit() ([]AuditEntry, error) {
	var out struct {
		Audit []AuditEntry `json:"audit"`
	}
	if err := c.get("/api/admin/audit", &out); err != nil {
		return nil, err
	}
	return out.Audit, nil
}

// get performs an authenticated GET and decodes JSON into out.
func (c AdminClient) get(path string, out any) error {
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, trimSlash(c.ServerURL)+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// List returns all licenses via the admin API.
func (c AdminClient) List() ([]AdminLicense, error) {
	var out struct {
		Licenses []AdminLicense `json:"licenses"`
	}
	if err := c.get("/api/admin/list", &out); err != nil {
		return nil, err
	}
	return out.Licenses, nil
}
