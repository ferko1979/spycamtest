// Package alerts tracks a baseline of known devices on the local network and
// emits events when a new device — or a new likely camera — appears. Events
// can be delivered to a generic webhook (e.g. Slack/Discord/automation).
//
// This is for networks you own or are authorized to monitor; it is the
// pro-privacy side of the app (knowing when an unexpected camera joins).
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event describes something worth notifying about.
type Event struct {
	Kind     string    `json:"kind"` // "new_device" | "new_camera"
	IP       string    `json:"ip"`
	MAC      string    `json:"mac"`
	Vendor   string    `json:"vendor,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	At       time.Time `json:"at"`
	Message  string    `json:"message"`
}

// Seen is the minimal device shape the baseline needs; netscan.Device
// satisfies it structurally via Observed.
type Observed struct {
	IP       string
	MAC      string
	Vendor   string
	Hostname string
	Camera   bool
}

// Baseline is a persisted set of known device MACs plus which were cameras.
type Baseline struct {
	Path string

	mu    sync.Mutex
	known map[string]bool // mac -> wasCamera
}

type baselineFile struct {
	Known map[string]bool `json:"known"` // mac -> wasCamera
}

func normMAC(m string) string { return strings.ToLower(strings.TrimSpace(m)) }

// Load reads the baseline from disk (empty if absent/malformed).
func (b *Baseline) Load() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.known = map[string]bool{}
	if b.Path == "" {
		return
	}
	data, err := os.ReadFile(b.Path)
	if err != nil {
		return
	}
	var bf baselineFile
	if json.Unmarshal(data, &bf) == nil && bf.Known != nil {
		for k, v := range bf.Known {
			b.known[normMAC(k)] = v
		}
	}
}

func (b *Baseline) save() error {
	if b.Path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(b.Path), 0o755); err != nil {
		return err
	}
	bf := baselineFile{Known: b.known}
	data, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(b.Path, data, 0o600)
}

// Diff compares observed devices against the baseline and returns events for
// devices never seen before, and for devices newly identified as cameras
// (even if the MAC was already known). It does not mutate the baseline.
func (b *Baseline) Diff(obs []Observed) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.known == nil {
		b.known = map[string]bool{}
	}
	var events []Event
	now := time.Now()
	for _, o := range obs {
		mac := normMAC(o.MAC)
		if mac == "" {
			continue
		}
		wasCamera, seen := b.known[mac]
		if !seen {
			events = append(events, Event{
				Kind: "new_device", IP: o.IP, MAC: mac, Vendor: o.Vendor,
				Hostname: o.Hostname, At: now,
				Message: "New device joined: " + o.IP + " (" + mac + ") " + o.Vendor,
			})
			if o.Camera {
				events = append(events, Event{
					Kind: "new_camera", IP: o.IP, MAC: mac, Vendor: o.Vendor,
					Hostname: o.Hostname, At: now,
					Message: "New likely CAMERA detected: " + o.IP + " (" + mac + ") " + o.Vendor,
				})
			}
		} else if o.Camera && !wasCamera {
			events = append(events, Event{
				Kind: "new_camera", IP: o.IP, MAC: mac, Vendor: o.Vendor,
				Hostname: o.Hostname, At: now,
				Message: "Known device now identified as a CAMERA: " + o.IP + " (" + mac + ")",
			})
		}
	}
	// Sort for deterministic output.
	sort.Slice(events, func(i, j int) bool {
		if events[i].MAC != events[j].MAC {
			return events[i].MAC < events[j].MAC
		}
		return events[i].Kind < events[j].Kind
	})
	return events
}

// Update folds the observed devices into the baseline and persists it.
func (b *Baseline) Update(obs []Observed) error {
	b.mu.Lock()
	if b.known == nil {
		b.known = map[string]bool{}
	}
	for _, o := range obs {
		mac := normMAC(o.MAC)
		if mac == "" {
			continue
		}
		// Preserve a prior camera=true even if a later passive scan misses it.
		b.known[mac] = b.known[mac] || o.Camera
	}
	err := b.save()
	b.mu.Unlock()
	return err
}

// Known returns a snapshot count of known devices.
func (b *Baseline) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.known)
}

// Webhook posts events as JSON to a URL. Empty URL disables delivery.
type Webhook struct {
	URL    string
	Client *http.Client
}

// Send posts the events (if any, and if configured). It sends one POST with
// a JSON body {"events":[...]} and also a "text" summary field that chat
// webhooks (Slack/Discord/Mattermost) render directly.
func (h Webhook) Send(ctx context.Context, events []Event) error {
	if h.URL == "" || len(events) == 0 {
		return nil
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	var lines []string
	for _, e := range events {
		lines = append(lines, "• "+e.Message)
	}
	payload := map[string]any{
		"text":   "SpyCam alerts:\n" + strings.Join(lines, "\n"),
		"events": events,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
