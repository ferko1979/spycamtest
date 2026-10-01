// Package report turns accumulated activity usage into a "work verifier"
// report, exports it as JSON or CSV, and keeps a local append-only history.
//
// Reports are built from disclosed activity tracking (see package activity):
// each report records whether tracking was disclosed/consented and who the
// subject is, so the artifact itself carries its provenance rather than
// hiding it.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"spycam-tray-agent/internal/activity"
)

// Report is a single work-verifier snapshot.
type Report struct {
	GeneratedAt   time.Time        `json:"generated_at"`
	Host          string           `json:"host"`
	User          string           `json:"user"`
	WindowStart   time.Time        `json:"window_start"`
	WindowEnd     time.Time        `json:"window_end"`
	ActiveSeconds float64          `json:"active_seconds"`
	IdleSeconds   float64          `json:"idle_seconds"`
	TotalSeconds  float64          `json:"total_seconds"`
	Entries       []activity.Usage `json:"entries"`

	// Categories is per-category active time (Development, Communication,
	// etc.), derived from the entries. Idle time is excluded.
	Categories []CategoryTotal `json:"categories,omitempty"`

	// Signature, when present, makes the report tamper-evident. It is
	// excluded from the signed payload (see SigningPayload).
	Signature *Signature `json:"signature,omitempty"`

	// Disclosed records that the monitored user was informed and consented.
	// It is always set true by Build because this tool only produces reports
	// for disclosed tracking; it is surfaced in the report so downstream
	// consumers can see the basis on which data was collected.
	Disclosed bool `json:"disclosed"`
}

// Meta carries identity/consent context for a report.
type Meta struct {
	Host string
	User string
}

// Build assembles a Report from usage snapshot and the window bounds.
// Idle time (the activity.IdleKey bucket) is separated from active time.
func Build(usage []activity.Usage, since, until time.Time, meta Meta) Report {
	r := Report{
		GeneratedAt: until,
		Host:        meta.Host,
		User:        meta.User,
		WindowStart: since,
		WindowEnd:   until,
		Disclosed:   true,
	}
	entries := make([]activity.Usage, 0, len(usage))
	for _, u := range usage {
		if u.App == "(idle)" {
			r.IdleSeconds += u.Seconds
			continue
		}
		r.ActiveSeconds += u.Seconds
		entries = append(entries, u)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Seconds > entries[j].Seconds })
	r.Entries = entries
	r.TotalSeconds = r.ActiveSeconds + r.IdleSeconds
	r.Categories = categorize(entries, nil)
	return r
}

// categorize aggregates active entries into per-category totals, sorted by
// descending time. custom is an optional override rule set.
func categorize(entries []activity.Usage, custom map[string][]string) []CategoryTotal {
	byCat := map[string]float64{}
	for _, e := range entries {
		byCat[Categorize(e.App, e.Title, custom)] += e.Seconds
	}
	out := make([]CategoryTotal, 0, len(byCat))
	for c, s := range byCat {
		out = append(out, CategoryTotal{Category: c, Seconds: s})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seconds != out[j].Seconds {
			return out[i].Seconds > out[j].Seconds
		}
		return out[i].Category < out[j].Category
	})
	return out
}

// JSON renders the report as indented JSON.
func (r Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// WriteCSV writes the report entries as CSV to w, with a header row and a
// trailing idle row. Columns: app, window_title, seconds, minutes.
func (r Report) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{"app", "window_title", "seconds", "minutes"}); err != nil {
		return err
	}
	for _, e := range r.Entries {
		if err := cw.Write([]string{
			e.App,
			e.Title,
			strconv.FormatFloat(e.Seconds, 'f', 1, 64),
			strconv.FormatFloat(e.Seconds/60, 'f', 2, 64),
		}); err != nil {
			return err
		}
	}
	if r.IdleSeconds > 0 {
		if err := cw.Write([]string{
			"(idle)", "",
			strconv.FormatFloat(r.IdleSeconds, 'f', 1, 64),
			strconv.FormatFloat(r.IdleSeconds/60, 'f', 2, 64),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// History is an append-only JSONL file of reports.
type History struct {
	Path string
}

// Append writes one report as a JSON line to the history file, creating
// parent directories as needed.
func (h History) Append(r Report) error {
	if h.Path == "" {
		return fmt.Errorf("history path not set")
	}
	if err := os.MkdirAll(filepath.Dir(h.Path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(h.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// Load reads up to the last n reports from the history file (n <= 0 means
// all). Malformed lines are skipped.
func (h History) Load(n int) ([]Report, error) {
	data, err := os.ReadFile(h.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var all []Report
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			line := data[start:i]
			start = i + 1
			var r Report
			if json.Unmarshal(line, &r) == nil {
				all = append(all, r)
			}
		}
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}
