package license

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Verifier is the subset of Client the Manager needs (so tests can stub it).
type Verifier interface {
	VerifyCode(ctx context.Context, code string) (Claims, error)
}

// CodeStatus is the last outcome for one configured code.
type CodeStatus struct {
	Code     string   `json:"code"`
	Valid    bool     `json:"valid"`
	Plan     string   `json:"plan,omitempty"`
	Features []string `json:"features,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Entitlement is the aggregate result across all configured codes.
type Entitlement struct {
	Features  []string     `json:"features"`
	Codes     []CodeStatus `json:"codes"`
	LastGood  time.Time    `json:"last_good"`
	LastCheck time.Time    `json:"last_check"`
	InGrace   bool         `json:"in_grace"`
	Degraded  bool         `json:"degraded"` // running on base features only
	LastError string       `json:"last_error,omitempty"`
}

// Manager keeps the current entitlement, refreshing it against the server and
// unioning the features granted by every valid code. If all checks fail it
// keeps the last-known features for GraceWindow, then falls back to Base.
type Manager struct {
	verifier Verifier
	base     []string // features always available (e.g. none, or {scan})
	grace    time.Duration

	mu    sync.RWMutex
	codes []string
	ent   Entitlement
	now   func() time.Time
}

// NewManager builds a Manager. base features are granted even with no valid
// license; grace is how long to retain features after the server goes away.
func NewManager(v Verifier, base []string, grace time.Duration) *Manager {
	m := &Manager{verifier: v, base: dedup(base), grace: grace, now: time.Now}
	m.ent.Features = append([]string(nil), m.base...)
	m.ent.Degraded = true
	return m
}

// SetCodes replaces the configured license codes.
func (m *Manager) SetCodes(codes []string) {
	m.mu.Lock()
	m.codes = append([]string(nil), codes...)
	m.mu.Unlock()
}

// SetVerifier swaps the verifier (e.g. after the server URL or pinned key
// changes in config).
func (m *Manager) SetVerifier(v Verifier) {
	m.mu.Lock()
	m.verifier = v
	m.mu.Unlock()
}

// Refresh verifies all codes and updates the entitlement.
func (m *Manager) Refresh(ctx context.Context) {
	m.mu.RLock()
	codes := append([]string(nil), m.codes...)
	v := m.verifier
	m.mu.RUnlock()

	now := m.now()
	union := map[string]bool{}
	for _, f := range m.base {
		union[f] = true
	}
	var statuses []CodeStatus
	anyValid := false

	for _, code := range codes {
		if code == "" {
			continue
		}
		claims, err := v.VerifyCode(ctx, code)
		st := CodeStatus{Code: maskCode(code)}
		if err != nil {
			st.Error = err.Error()
			statuses = append(statuses, st)
			continue
		}
		st.Valid = claims.Valid
		st.Plan = claims.Plan
		st.Features = claims.Features
		st.Reason = claims.Reason
		if claims.Valid {
			anyValid = true
			for _, f := range claims.Features {
				union[f] = true
			}
		}
		statuses = append(statuses, st)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.ent.Codes = statuses
	m.ent.LastCheck = now
	m.ent.LastError = ""

	hadCodes := len(codes) > 0
	if anyValid || !hadCodes {
		// Success (or nothing to check): adopt the union now.
		m.ent.Features = sortedKeys(union)
		m.ent.LastGood = now
		m.ent.InGrace = false
		m.ent.Degraded = !anyValid // degraded only if truly unlicensed
		return
	}

	// No valid code this round. Keep last-known features within grace.
	withinGrace := !m.ent.LastGood.IsZero() && now.Sub(m.ent.LastGood) <= m.grace
	if withinGrace {
		m.ent.InGrace = true
		m.ent.Degraded = false
		// keep existing m.ent.Features
	} else {
		m.ent.Features = append([]string(nil), m.base...)
		m.ent.InGrace = false
		m.ent.Degraded = true
	}
}

// Has reports whether the current entitlement includes a feature.
func (m *Manager) Has(feature string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Has(m.ent.Features, feature)
}

// Snapshot returns a copy of the current entitlement.
func (m *Manager) Snapshot() Entitlement {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e := m.ent
	e.Features = append([]string(nil), m.ent.Features...)
	e.Codes = append([]CodeStatus(nil), m.ent.Codes...)
	return e
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// maskCode hides all but the last 4 characters of a code for display/logs.
func maskCode(code string) string {
	if len(code) <= 4 {
		return "****"
	}
	return "****" + code[len(code)-4:]
}
