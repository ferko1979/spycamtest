// Package activity implements a transparent foreground-activity tracker:
// it periodically samples the active application (process name) and window
// title and accumulates the time spent in each, with idle detection.
//
// Transparency is a design requirement, not an option. The tracker only
// runs while Enabled is true, which the caller must set based on explicit,
// informed user consent. The intended deployment (see package main) shows a
// persistent, visible indicator while tracking is active and lets the person
// on the machine see their own data and stop tracking. This package does not
// attempt to hide itself, evade task managers, or capture keystrokes,
// screen contents, clipboard, or passwords — only the active app/title and
// time, which is what a disclosed work/productivity tracker needs.
package activity

import (
	"sort"
	"sync"
	"time"
)

// Foreground is a single observation of what is active on screen.
type Foreground struct {
	App   string // process/application name, e.g. "chrome.exe" / "Code"
	Title string // active window title
}

// Sampler returns the current foreground app/title. Implementations are
// platform-specific. An error (or empty App) is treated as "unknown" and
// skipped rather than fatal.
type Sampler interface {
	Foreground() (Foreground, error)
}

// IdleReporter reports how long the user has been idle (no input). Optional;
// if nil, idle detection is disabled and all sampled time counts as active.
type IdleReporter interface {
	IdleFor() (time.Duration, error)
}

// Usage is accumulated time for one (app, title) pair.
type Usage struct {
	App     string        `json:"app"`
	Title   string        `json:"title"`
	Seconds float64       `json:"seconds"`
	d       time.Duration // internal accumulator
}

// Tracker samples the foreground on an interval and accumulates usage.
// It is safe for concurrent use.
type Tracker struct {
	sampler  Sampler
	idle     IdleReporter
	interval time.Duration
	// idleThreshold: if the user has been idle at least this long, samples
	// are attributed to an "(idle)" bucket instead of the active window.
	idleThreshold time.Duration

	mu      sync.Mutex
	enabled bool
	usage   map[string]*Usage // key: app + "\x00" + title
	since   time.Time
	stopCh  chan struct{}
	running bool

	now func() time.Time // injectable clock for tests
}

// Options configures a Tracker.
type Options struct {
	Interval      time.Duration
	IdleThreshold time.Duration
	Idle          IdleReporter
}

// New creates a Tracker. Tracking does not begin until Start is called AND
// SetEnabled(true) has been set from user consent.
func New(s Sampler, opts Options) *Tracker {
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Second
	}
	if opts.IdleThreshold <= 0 {
		opts.IdleThreshold = 3 * time.Minute
	}
	return &Tracker{
		sampler:       s,
		idle:          opts.Idle,
		interval:      opts.Interval,
		idleThreshold: opts.IdleThreshold,
		usage:         map[string]*Usage{},
		now:           time.Now,
	}
}

// SetEnabled turns accumulation on or off. This is the consent gate: callers
// set it true only after the user has been informed and agreed, and must
// expose a way for the user to set it false.
func (t *Tracker) SetEnabled(v bool) {
	t.mu.Lock()
	t.enabled = v
	t.mu.Unlock()
}

// Enabled reports whether accumulation is currently on.
func (t *Tracker) Enabled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.enabled
}

const idleKey = "(idle)"

// accumulate adds dt to the bucket for fg (or the idle bucket). Caller holds
// the lock. Exposed logic kept separate so tests can drive it deterministically.
func (t *Tracker) accumulate(fg Foreground, idleFor time.Duration, dt time.Duration) {
	if !t.enabled || dt <= 0 {
		return
	}
	app, title := fg.App, fg.Title
	if idleFor >= t.idleThreshold {
		app, title = idleKey, ""
	} else if app == "" {
		return // unknown foreground, skip
	}
	key := app + "\x00" + title
	u := t.usage[key]
	if u == nil {
		u = &Usage{App: app, Title: title}
		t.usage[key] = u
	}
	u.d += dt
	u.Seconds = u.d.Seconds()
}

// tick performs one sample+accumulate cycle using the configured sampler.
func (t *Tracker) tick(dt time.Duration) {
	if !t.Enabled() {
		return
	}
	fg, err := t.sampler.Foreground()
	if err != nil {
		return
	}
	var idleFor time.Duration
	if t.idle != nil {
		if d, err := t.idle.IdleFor(); err == nil {
			idleFor = d
		}
	}
	t.mu.Lock()
	t.accumulate(fg, idleFor, dt)
	t.mu.Unlock()
}

// Start begins the sampling loop in a goroutine. It is a no-op if already
// running. Stop ends it.
func (t *Tracker) Start() {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return
	}
	t.running = true
	t.since = t.now()
	t.stopCh = make(chan struct{})
	stop := t.stopCh
	t.mu.Unlock()

	go func() {
		ticker := time.NewTicker(t.interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				t.tick(t.interval)
			}
		}
	}()
}

// Stop ends the sampling loop.
func (t *Tracker) Stop() {
	t.mu.Lock()
	if t.running && t.stopCh != nil {
		close(t.stopCh)
		t.stopCh = nil
	}
	t.running = false
	t.mu.Unlock()
}

// Snapshot returns the accumulated usage sorted by descending time, plus the
// time the current accumulation window started.
func (t *Tracker) Snapshot() (usage []Usage, since time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	usage = make([]Usage, 0, len(t.usage))
	for _, u := range t.usage {
		usage = append(usage, Usage{App: u.App, Title: u.Title, Seconds: u.d.Seconds()})
	}
	sort.Slice(usage, func(i, j int) bool { return usage[i].Seconds > usage[j].Seconds })
	return usage, t.since
}

// Reset clears accumulated usage (e.g. after a report is flushed) and
// restarts the accumulation window.
func (t *Tracker) Reset() {
	t.mu.Lock()
	t.usage = map[string]*Usage{}
	t.since = t.now()
	t.mu.Unlock()
}
