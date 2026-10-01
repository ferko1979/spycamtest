package report

import (
	"testing"
	"time"

	"spycam-tray-agent/internal/activity"
)

func TestCategorize(t *testing.T) {
	cases := []struct{ app, title, want string }{
		{"Code.exe", "main.go — project", "Development"},
		{"chrome.exe", "Gmail", "Communication"}, // mail keyword wins over browser
		{"chrome.exe", "some website", "Browsing"},
		{"slack.exe", "general", "Communication"},
		{"EXCEL.EXE", "budget.xlsx", "Productivity"},
		{"spotify.exe", "playlist", "Media"},
		{"weirdapp", "nothing", "Other"},
		{"(idle)", "", "Idle"},
	}
	for _, c := range cases {
		if got := Categorize(c.app, c.title, nil); got != c.want {
			t.Errorf("Categorize(%q,%q) = %q, want %q", c.app, c.title, got, c.want)
		}
	}
}

func TestCategorizeCustomOverride(t *testing.T) {
	custom := map[string][]string{"Gaming": {"steam"}}
	if got := Categorize("steam.exe", "Library", custom); got != "Gaming" {
		t.Errorf("custom rule = %q, want Gaming", got)
	}
}

func TestBuildIncludesCategories(t *testing.T) {
	usage := []activity.Usage{
		{App: "code", Title: "x", Seconds: 100},
		{App: "slack", Title: "y", Seconds: 40},
		{App: "(idle)", Title: "", Seconds: 10},
	}
	r := Build(usage, time.Now(), time.Now(), Meta{})
	if len(r.Categories) < 2 {
		t.Fatalf("expected categories, got %+v", r.Categories)
	}
	// Development (100) should sort before Communication (40); Idle excluded.
	if r.Categories[0].Category != "Development" || r.Categories[0].Seconds != 100 {
		t.Errorf("top category = %+v", r.Categories[0])
	}
	for _, c := range r.Categories {
		if c.Category == "Idle" {
			t.Error("idle should not appear in categories")
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	seed, err := GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	r := Build([]activity.Usage{{App: "code", Title: "x", Seconds: 60}}, time.Now(), time.Now(), Meta{User: "alice"})

	if r.Verify() {
		t.Error("unsigned report should not verify")
	}
	if err := r.Sign(seed); err != nil {
		t.Fatal(err)
	}
	if r.Signature == nil || r.Signature.Algo != "ed25519" {
		t.Fatalf("signature not attached: %+v", r.Signature)
	}
	if !r.Verify() {
		t.Error("signed report should verify")
	}

	// Tampering invalidates the signature.
	r.ActiveSeconds += 1
	if r.Verify() {
		t.Error("tampered report must not verify")
	}
}

func TestSignNoSeed(t *testing.T) {
	r := Build(nil, time.Now(), time.Now(), Meta{})
	if err := r.Sign(""); err == nil {
		t.Error("signing without a seed should error")
	}
}
