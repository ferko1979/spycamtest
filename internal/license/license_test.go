package license

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestStore(t *testing.T, licenses map[string]*License) *Store {
	t.Helper()
	seed, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(licenses, seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServerSignAndClientVerify(t *testing.T) {
	store := newTestStore(t, map[string]*License{
		"PRO-123": {Plan: "pro", Features: []string{FeatureScan, FeatureActiveScan, FeatureCameras}},
	})
	srv := httptest.NewServer(store.Handler())
	defer srv.Close()

	c := Client{ServerURL: srv.URL, DeviceID: "dev-1", PinnedPubKey: store.PublicKey()}
	claims, err := c.VerifyCode(context.Background(), "PRO-123")
	if err != nil {
		t.Fatal(err)
	}
	if !claims.Valid || claims.Plan != "pro" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !Has(claims.Features, FeatureCameras) || Has(claims.Features, FeatureActivity) {
		t.Errorf("features wrong: %v", claims.Features)
	}
}

func TestClientRejectsWrongPinnedKey(t *testing.T) {
	store := newTestStore(t, map[string]*License{"X": {Features: []string{FeatureScan}}})
	srv := httptest.NewServer(store.Handler())
	defer srv.Close()

	_, otherPub, _ := GenerateKeypair()
	c := Client{ServerURL: srv.URL, DeviceID: "d", PinnedPubKey: otherPub}
	if _, err := c.VerifyCode(context.Background(), "X"); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("expected key mismatch, got %v", err)
	}
}

func TestUnknownAndExpiredCodes(t *testing.T) {
	store := newTestStore(t, map[string]*License{
		"OLD": {Features: []string{FeatureScan}, Expires: time.Now().Add(-time.Hour)},
	})
	srv := httptest.NewServer(store.Handler())
	defer srv.Close()
	c := Client{ServerURL: srv.URL, DeviceID: "d", PinnedPubKey: store.PublicKey()}

	if claims, _ := c.VerifyCode(context.Background(), "NOPE"); claims.Valid {
		t.Error("unknown code should be invalid")
	}
	claims, _ := c.VerifyCode(context.Background(), "OLD")
	if claims.Valid || claims.Reason != "license expired" {
		t.Errorf("expired code handling wrong: %+v", claims)
	}
}

func TestDeviceSeatLimit(t *testing.T) {
	store := newTestStore(t, map[string]*License{
		"SEAT": {Features: []string{FeatureScan}, MaxDevices: 1},
	})
	srv := httptest.NewServer(store.Handler())
	defer srv.Close()

	c1 := Client{ServerURL: srv.URL, DeviceID: "dev-A", PinnedPubKey: store.PublicKey()}
	c2 := Client{ServerURL: srv.URL, DeviceID: "dev-B", PinnedPubKey: store.PublicKey()}

	if claims, _ := c1.VerifyCode(context.Background(), "SEAT"); !claims.Valid {
		t.Fatal("first device should bind")
	}
	// Same device re-verifies fine.
	if claims, _ := c1.VerifyCode(context.Background(), "SEAT"); !claims.Valid {
		t.Fatal("same device should re-verify")
	}
	// Second device exceeds the seat limit.
	if claims, _ := c2.VerifyCode(context.Background(), "SEAT"); claims.Valid {
		t.Errorf("second device should be rejected: %+v", claims)
	}
}

// stubVerifier drives the Manager deterministically.
type stubVerifier struct {
	claims map[string]Claims
	err    error
}

func (s stubVerifier) VerifyCode(_ context.Context, code string) (Claims, error) {
	if s.err != nil {
		return Claims{}, s.err
	}
	c, ok := s.claims[code]
	if !ok {
		return Claims{Code: code, Valid: false, Reason: "unknown"}, nil
	}
	return c, nil
}

func TestManagerUnionAndGrace(t *testing.T) {
	cur := time.Now()
	v := stubVerifier{claims: map[string]Claims{
		"A": {Valid: true, Features: []string{FeatureScan, FeatureActivity}},
		"B": {Valid: true, Features: []string{FeatureCameras}},
	}}
	m := NewManager(v, []string{FeatureScan}, time.Hour)
	m.now = func() time.Time { return cur }
	m.SetCodes([]string{"A", "B"})

	m.Refresh(context.Background())
	for _, f := range []string{FeatureScan, FeatureActivity, FeatureCameras} {
		if !m.Has(f) {
			t.Errorf("expected feature %s after union", f)
		}
	}
	if m.Has(FeatureAlerts) {
		t.Error("alerts should not be granted")
	}

	// Server goes away: within grace, keep features.
	failing := &Manager{verifier: stubVerifier{err: errors.New("down")}, base: []string{FeatureScan}, grace: time.Hour, now: func() time.Time { return cur.Add(30 * time.Minute) }}
	failing.ent = m.Snapshot()
	failing.SetCodes([]string{"A", "B"})
	failing.Refresh(context.Background())
	if !failing.Has(FeatureActivity) {
		t.Error("within grace, features should persist")
	}
	if !failing.Snapshot().InGrace {
		t.Error("should report in-grace")
	}

	// Past grace: fall back to base only.
	failing.now = func() time.Time { return cur.Add(2 * time.Hour) }
	failing.Refresh(context.Background())
	if failing.Has(FeatureActivity) {
		t.Error("past grace, gated features should drop")
	}
	if !failing.Has(FeatureScan) {
		t.Error("base feature should remain")
	}
	if !failing.Snapshot().Degraded {
		t.Error("should report degraded past grace")
	}
}

func TestManagerCodeMasking(t *testing.T) {
	v := stubVerifier{claims: map[string]Claims{"SECRET-TOKEN-9999": {Valid: true, Features: []string{FeatureScan}}}}
	m := NewManager(v, nil, time.Hour)
	m.SetCodes([]string{"SECRET-TOKEN-9999"})
	m.Refresh(context.Background())
	for _, cs := range m.Snapshot().Codes {
		if cs.Code == "SECRET-TOKEN-9999" {
			t.Error("raw code should not appear in status")
		}
		if cs.Code != "****9999" {
			t.Errorf("unexpected masked code %q", cs.Code)
		}
	}
}
