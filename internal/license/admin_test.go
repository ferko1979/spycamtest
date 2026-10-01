package license

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminIssueRevokeDeleteFlow(t *testing.T) {
	store := newTestStore(t, nil)
	store.SetAdminToken("admin-secret")
	srv := httptest.NewServer(store.Handler())
	defer srv.Close()

	admin := AdminClient{ServerURL: srv.URL, Token: "admin-secret"}
	verifier := Client{ServerURL: srv.URL, DeviceID: "d1", PinnedPubKey: store.PublicKey()}

	// Issue a code.
	al, err := admin.Issue(IssueRequest{Plan: "pro", Features: []string{FeatureScan, FeatureCameras}, MaxDevices: 2})
	if err != nil {
		t.Fatal(err)
	}
	if al.Code == "" {
		t.Fatal("expected a generated code")
	}

	// It verifies as valid with the right features.
	claims, err := verifier.VerifyCode(context.Background(), al.Code)
	if err != nil || !claims.Valid || !Has(claims.Features, FeatureCameras) {
		t.Fatalf("issued code should verify: %+v err=%v", claims, err)
	}

	// Revoke it -> now invalid.
	if err := admin.Revoke(al.Code); err != nil {
		t.Fatal(err)
	}
	if claims, _ := verifier.VerifyCode(context.Background(), al.Code); claims.Valid {
		t.Error("revoked code should be invalid")
	}

	// Enable again -> valid.
	if err := admin.Enable(al.Code); err != nil {
		t.Fatal(err)
	}
	if claims, _ := verifier.VerifyCode(context.Background(), al.Code); !claims.Valid {
		t.Error("re-enabled code should be valid")
	}

	// List shows it.
	list, err := admin.List()
	if err != nil || len(list) != 1 || list[0].Code != al.Code {
		t.Fatalf("list mismatch: %+v err=%v", list, err)
	}

	// Delete -> gone.
	if err := admin.Delete(al.Code); err != nil {
		t.Fatal(err)
	}
	if claims, _ := verifier.VerifyCode(context.Background(), al.Code); claims.Valid {
		t.Error("deleted code should be invalid")
	}
}

func TestAdminRequiresToken(t *testing.T) {
	store := newTestStore(t, nil)
	store.SetAdminToken("secret")
	srv := httptest.NewServer(store.Handler())
	defer srv.Close()

	// Wrong token -> 403.
	wrong := AdminClient{ServerURL: srv.URL, Token: "nope"}
	if _, err := wrong.Issue(IssueRequest{Plan: "p", Features: []string{FeatureScan}}); err == nil {
		t.Error("issue with wrong token should fail")
	}

	// No admin token configured -> admin disabled (403).
	store2 := newTestStore(t, nil) // no SetAdminToken
	srv2 := httptest.NewServer(store2.Handler())
	defer srv2.Close()
	req, _ := http.NewRequest(http.MethodGet, srv2.URL+"/api/admin/list", nil)
	req.Header.Set("Authorization", "Bearer anything")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("admin disabled should be 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAuditAndUsage(t *testing.T) {
	store := newTestStore(t, nil)
	store.SetAdminToken("adm")
	srv := httptest.NewServer(store.Handler())
	defer srv.Close()
	admin := AdminClient{ServerURL: srv.URL, Token: "adm"}
	verifier := Client{ServerURL: srv.URL, DeviceID: "dev-7", PinnedPubKey: store.PublicKey()}

	al, err := admin.Issue(IssueRequest{Plan: "pro", Features: []string{FeatureScan}})
	if err != nil {
		t.Fatal(err)
	}
	// A verify records a device check-in.
	if _, err := verifier.VerifyCode(context.Background(), al.Code); err != nil {
		t.Fatal(err)
	}
	list, _ := admin.List()
	if len(list) != 1 || list[0].DeviceSeen["dev-7"].IsZero() {
		t.Errorf("expected device check-in recorded: %+v", list)
	}

	// Audit log has the issue action.
	entries, err := admin.Audit()
	if err != nil {
		t.Fatal(err)
	}
	foundIssue := false
	for _, e := range entries {
		if e.Action == "issue" && e.Code == al.Code && e.OK {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("issue action not in audit log: %+v", entries)
	}

	// Revoke adds another audit entry.
	_ = admin.Revoke(al.Code)
	entries, _ = admin.Audit()
	if len(entries) < 2 {
		t.Errorf("expected >=2 audit entries, got %d", len(entries))
	}
}

func TestExpiryInClaims(t *testing.T) {
	store := newTestStore(t, nil)
	store.SetAdminToken("adm")
	srv := httptest.NewServer(store.Handler())
	defer srv.Close()
	admin := AdminClient{ServerURL: srv.URL, Token: "adm"}
	al, err := admin.Issue(IssueRequest{Plan: "pro", Features: []string{FeatureScan}, ExpiresDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	c := Client{ServerURL: srv.URL, DeviceID: "d", PinnedPubKey: store.PublicKey()}
	claims, _ := c.VerifyCode(context.Background(), al.Code)
	if claims.Expires.IsZero() {
		t.Error("expected non-zero expiry in claims")
	}
}

func TestIssueValidation(t *testing.T) {
	store := newTestStore(t, nil)
	if _, err := store.Issue(IssueRequest{Plan: "", Features: []string{FeatureScan}}); err == nil {
		t.Error("empty plan should error")
	}
	if _, err := store.Issue(IssueRequest{Plan: "p", Features: nil}); err == nil {
		t.Error("no features should error")
	}
}
