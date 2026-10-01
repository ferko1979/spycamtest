package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestDiffNewDeviceAndCamera(t *testing.T) {
	b := &Baseline{Path: filepath.Join(t.TempDir(), "b.json")}
	b.Load()

	obs := []Observed{
		{IP: "192.168.1.5", MAC: "AA:BB:CC:00:00:01", Vendor: "Acme"},
		{IP: "192.168.1.6", MAC: "AA:BB:CC:00:00:02", Vendor: "Hikvision", Camera: true},
	}
	ev := b.Diff(obs)
	// device1 -> new_device; device2 -> new_device + new_camera
	if len(ev) != 3 {
		t.Fatalf("expected 3 events, got %d: %+v", len(ev), ev)
	}

	// After update, same observation yields no events.
	if err := b.Update(obs); err != nil {
		t.Fatal(err)
	}
	if ev2 := b.Diff(obs); len(ev2) != 0 {
		t.Errorf("known devices should not re-alert, got %+v", ev2)
	}

	// A known non-camera that becomes a camera -> new_camera only.
	obs[0].Camera = true
	ev3 := b.Diff(obs[:1])
	if len(ev3) != 1 || ev3[0].Kind != "new_camera" {
		t.Errorf("expected single new_camera event, got %+v", ev3)
	}
}

func TestBaselinePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.json")
	b1 := &Baseline{Path: path}
	b1.Load()
	_ = b1.Update([]Observed{{MAC: "AA:BB:CC:00:00:01", Camera: true}})

	b2 := &Baseline{Path: path}
	b2.Load()
	if b2.Count() != 1 {
		t.Fatalf("reloaded baseline count = %d, want 1", b2.Count())
	}
	// Camera flag preserved -> no new_camera on re-observe.
	if ev := b2.Diff([]Observed{{MAC: "AA:BB:CC:00:00:01", Camera: true}}); len(ev) != 0 {
		t.Errorf("camera flag not preserved across reload: %+v", ev)
	}
}

func TestWebhookSend(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	h := Webhook{URL: srv.URL}
	events := []Event{{Kind: "new_camera", IP: "1.2.3.4", MAC: "aa", Message: "cam!"}}
	if err := h.Send(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if got["text"] == nil || len(got["events"].([]any)) != 1 {
		t.Errorf("webhook payload missing fields: %+v", got)
	}
}

func TestWebhookDisabledNoop(t *testing.T) {
	// Empty URL or no events -> no error, no call.
	if err := (Webhook{}).Send(context.Background(), []Event{{Message: "x"}}); err != nil {
		t.Errorf("empty URL should be a no-op, got %v", err)
	}
	if err := (Webhook{URL: "http://127.0.0.1:1"}).Send(context.Background(), nil); err != nil {
		t.Errorf("no events should be a no-op, got %v", err)
	}
}
