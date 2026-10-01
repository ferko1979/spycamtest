package report

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"spycam-tray-agent/internal/activity"
)

func sampleUsage() []activity.Usage {
	return []activity.Usage{
		{App: "code", Title: "main.go", Seconds: 120},
		{App: "chrome", Title: "docs", Seconds: 60},
		{App: "(idle)", Title: "", Seconds: 30},
	}
}

func TestBuild(t *testing.T) {
	since := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	until := since.Add(time.Hour)
	r := Build(sampleUsage(), since, until, Meta{Host: "pc1", User: "alice"})

	if r.ActiveSeconds != 180 {
		t.Errorf("active = %v, want 180", r.ActiveSeconds)
	}
	if r.IdleSeconds != 30 {
		t.Errorf("idle = %v, want 30", r.IdleSeconds)
	}
	if r.TotalSeconds != 210 {
		t.Errorf("total = %v, want 210", r.TotalSeconds)
	}
	if len(r.Entries) != 2 {
		t.Errorf("entries should exclude idle bucket, got %d", len(r.Entries))
	}
	if r.Entries[0].App != "code" {
		t.Errorf("entries not sorted desc: %+v", r.Entries)
	}
	if !r.Disclosed {
		t.Error("report should record disclosure")
	}
}

func TestWriteCSV(t *testing.T) {
	r := Build(sampleUsage(), time.Now(), time.Now(), Meta{})
	var buf bytes.Buffer
	if err := r.WriteCSV(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "app,window_title,seconds,minutes\n") {
		t.Errorf("missing/incorrect CSV header: %q", out)
	}
	if !strings.Contains(out, "code,main.go,120.0,2.00") {
		t.Errorf("missing code row: %q", out)
	}
	if !strings.Contains(out, "(idle),,30.0,0.50") {
		t.Errorf("missing idle row: %q", out)
	}
}

func TestHistoryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	h := History{Path: filepath.Join(dir, "history.jsonl")}

	// Empty history loads as nil, no error.
	if got, err := h.Load(0); err != nil || got != nil {
		t.Fatalf("empty load = %v, %v", got, err)
	}

	for i := 0; i < 3; i++ {
		r := Build(sampleUsage(), time.Now(), time.Now(), Meta{User: "u"})
		if err := h.Append(r); err != nil {
			t.Fatal(err)
		}
	}

	all, err := h.Load(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("loaded %d reports, want 3", len(all))
	}

	last2, _ := h.Load(2)
	if len(last2) != 2 {
		t.Errorf("Load(2) returned %d", len(last2))
	}
}
