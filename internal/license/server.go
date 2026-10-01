package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// License is a server-side record for one code.
type License struct {
	Plan       string               `json:"plan"`
	Features   []string             `json:"features"`
	Expires    time.Time            `json:"expires,omitempty"`     // zero = never
	MaxDevices int                  `json:"max_devices,omitempty"` // 0 = unlimited
	Devices    []string             `json:"devices,omitempty"`     // bound device ids
	Disabled   bool                 `json:"disabled,omitempty"`
	DeviceSeen map[string]time.Time `json:"device_seen,omitempty"` // device id -> last check-in
}

// Store holds licenses and the signing key. Safe for concurrent use.
type Store struct {
	mu         sync.Mutex
	licenses   map[string]*License
	priv       ed25519.PrivateKey
	pubB64     string
	now        func() time.Time
	onChange   func(map[string]*License) // optional persistence hook
	adminToken string
	audit      []AuditEntry     // in-memory ring of recent admin actions
	auditHook  func(AuditEntry) // optional sink (e.g. append to a file)
}

// SetAuditHook registers a sink called for every admin action (e.g. to append
// to a log file), in addition to the in-memory ring exposed via the API.
func (s *Store) SetAuditHook(fn func(AuditEntry)) {
	s.mu.Lock()
	s.auditHook = fn
	s.mu.Unlock()
}

// SetAdminToken enables the admin API. With an empty token (the default) the
// admin endpoints are disabled and respond 403.
func (s *Store) SetAdminToken(token string) {
	s.mu.Lock()
	s.adminToken = token
	s.mu.Unlock()
}

// NewStore builds a store from a code->License map and a signing seed.
func NewStore(licenses map[string]*License, seedB64 string) (*Store, error) {
	priv, err := PrivFromSeed(seedB64)
	if err != nil {
		return nil, err
	}
	if licenses == nil {
		licenses = map[string]*License{}
	}
	return &Store{
		licenses: licenses,
		priv:     priv,
		pubB64:   PubB64(priv),
		now:      time.Now,
	}, nil
}

// SetPersistHook registers a callback invoked (under lock) whenever device
// bindings change, so the caller can persist the updated license set.
func (s *Store) SetPersistHook(fn func(map[string]*License)) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

// PublicKey returns the base64 verifying key.
func (s *Store) PublicKey() string { return s.pubB64 }

// verify evaluates a request and returns claims (unsigned).
func (s *Store) verify(req VerifyRequest) Claims {
	now := s.now().UTC().Truncate(time.Second)
	c := Claims{Code: req.Code, DeviceID: req.DeviceID, Nonce: req.Nonce, IssuedAt: now}

	code := strings.TrimSpace(req.Code)
	if code == "" {
		c.Reason = "empty code"
		return c
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	lic, ok := s.licenses[code]
	if !ok {
		c.Reason = "unknown code"
		return c
	}
	if lic.Disabled {
		c.Reason = "license disabled"
		return c
	}
	if !lic.Expires.IsZero() && now.After(lic.Expires.UTC()) {
		c.Reason = "license expired"
		c.Expires = lic.Expires.UTC().Truncate(time.Second)
		return c
	}

	// Device binding / seat limit.
	if req.DeviceID != "" && lic.MaxDevices > 0 {
		bound := false
		for _, d := range lic.Devices {
			if d == req.DeviceID {
				bound = true
				break
			}
		}
		if !bound {
			if len(lic.Devices) >= lic.MaxDevices {
				c.Reason = "device limit reached"
				return c
			}
			lic.Devices = append(lic.Devices, req.DeviceID)
			if s.onChange != nil {
				s.onChange(s.licenses)
			}
		}
	}

	// Record the device check-in (usage reporting).
	if req.DeviceID != "" {
		if lic.DeviceSeen == nil {
			lic.DeviceSeen = map[string]time.Time{}
		}
		lic.DeviceSeen[req.DeviceID] = now
		if s.onChange != nil {
			s.onChange(s.licenses)
		}
	}

	c.Valid = true
	c.Plan = lic.Plan
	c.Features = append([]string(nil), lic.Features...)
	sort.Strings(c.Features)
	if !lic.Expires.IsZero() {
		c.Expires = lic.Expires.UTC().Truncate(time.Second)
	}
	return c
}

// sign wraps claims into a SignedResponse.
func (s *Store) sign(c Claims) (SignedResponse, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return SignedResponse{}, err
	}
	return SignedResponse{
		Claims:    payload,
		Algo:      "ed25519",
		PublicKey: s.pubB64,
		Signature: signClaims(s.priv, payload),
	}, nil
}

// Handler returns an http.Handler exposing:
//
//	POST /api/verify  -> SignedResponse
//	GET  /api/pubkey  -> {"public_key": "..."}
//	GET  /healthz     -> ok
func (s *Store) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req VerifyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp, err := s.sign(s.verify(req))
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, resp)
	})

	mux.HandleFunc("/api/pubkey", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"public_key": s.pubB64, "algo": "ed25519"})
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	s.registerAdminRoutes(mux)

	return mux
}

// Snapshot returns a copy of the current licenses (for persistence).
func (s *Store) Snapshot() map[string]License {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]License, len(s.licenses))
	for k, v := range s.licenses {
		out[k] = *v
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// RandomNonce returns a base64 random nonce.
func RandomNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
