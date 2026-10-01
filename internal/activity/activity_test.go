package activity

import (
	"testing"
	"time"
)

type fakeSampler struct{ fg Foreground }

func (f fakeSampler) Foreground() (Foreground, error) { return f.fg, nil }

func findUsage(us []Usage, app, title string) (Usage, bool) {
	for _, u := range us {
		if u.App == app && u.Title == title {
			return u, true
		}
	}
	return Usage{}, false
}

func TestAccumulateRequiresConsent(t *testing.T) {
	tr := New(fakeSampler{}, Options{})
	// Not enabled: accumulation is a no-op.
	tr.mu.Lock()
	tr.accumulate(Foreground{App: "chrome", Title: "x"}, 0, time.Second)
	tr.mu.Unlock()
	if us, _ := tr.Snapshot(); len(us) != 0 {
		t.Fatalf("no usage should accumulate without consent, got %v", us)
	}
}

func TestAccumulateAndIdle(t *testing.T) {
	tr := New(fakeSampler{}, Options{IdleThreshold: time.Minute})
	tr.SetEnabled(true)

	tr.mu.Lock()
	tr.accumulate(Foreground{App: "code", Title: "main.go"}, 0, 10*time.Second)
	tr.accumulate(Foreground{App: "code", Title: "main.go"}, 0, 5*time.Second)
	tr.accumulate(Foreground{App: "chrome", Title: "docs"}, 0, 7*time.Second)
	// Idle beyond threshold -> attributed to idle bucket.
	tr.accumulate(Foreground{App: "code", Title: "main.go"}, 2*time.Minute, 20*time.Second)
	// Unknown foreground (empty app) while active -> skipped.
	tr.accumulate(Foreground{App: "", Title: ""}, 0, 99*time.Second)
	tr.mu.Unlock()

	us, _ := tr.Snapshot()

	if u, ok := findUsage(us, "code", "main.go"); !ok || u.Seconds != 15 {
		t.Errorf("code/main.go = %+v (want 15s)", u)
	}
	if u, ok := findUsage(us, "chrome", "docs"); !ok || u.Seconds != 7 {
		t.Errorf("chrome/docs = %+v (want 7s)", u)
	}
	if u, ok := findUsage(us, idleKey, ""); !ok || u.Seconds != 20 {
		t.Errorf("idle bucket = %+v (want 20s)", u)
	}
	if _, ok := findUsage(us, "", ""); ok {
		t.Error("empty foreground should not be recorded")
	}

	// Snapshot is sorted descending by time.
	if len(us) >= 2 && us[0].Seconds < us[1].Seconds {
		t.Errorf("snapshot not sorted descending: %+v", us)
	}
}

func TestReset(t *testing.T) {
	tr := New(fakeSampler{}, Options{})
	tr.SetEnabled(true)
	tr.mu.Lock()
	tr.accumulate(Foreground{App: "a", Title: "b"}, 0, time.Second)
	tr.mu.Unlock()
	tr.Reset()
	if us, _ := tr.Snapshot(); len(us) != 0 {
		t.Errorf("usage should be empty after Reset, got %v", us)
	}
}

func TestEnabledToggle(t *testing.T) {
	tr := New(fakeSampler{}, Options{})
	if tr.Enabled() {
		t.Error("tracker should start disabled")
	}
	tr.SetEnabled(true)
	if !tr.Enabled() {
		t.Error("SetEnabled(true) failed")
	}
}
