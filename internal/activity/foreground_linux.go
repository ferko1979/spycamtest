//go:build linux

package activity

import (
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// linuxSampler reads the active window on X11 sessions using `xprop` and
// `xdotool` if present. On Wayland these tools typically cannot read other
// apps' window titles (by design), in which case the app name/title come
// back empty and only time totals are affected. It shells out to standard
// utilities; nothing is hidden from the user.
type linuxSampler struct{}

func NewSampler() Sampler { return linuxSampler{} }

func (linuxSampler) Foreground() (Foreground, error) {
	fg := Foreground{}

	// Active window id via xprop on the root window.
	idOut, err := exec.Command("sh", "-lc",
		`xprop -root _NET_ACTIVE_WINDOW 2>/dev/null | awk '{print $NF}'`).Output()
	if err != nil {
		return fg, nil // tools missing / not X11 — non-fatal
	}
	winID := strings.TrimSpace(string(idOut))
	if winID == "" || winID == "0x0" {
		return fg, nil
	}

	// Window title (_NET_WM_NAME) and class for app name.
	titleOut, _ := exec.Command("sh", "-lc",
		`xprop -id `+shellQuote(winID)+` _NET_WM_NAME 2>/dev/null`).Output()
	fg.Title = extractXpropString(string(titleOut))

	classOut, _ := exec.Command("sh", "-lc",
		`xprop -id `+shellQuote(winID)+` WM_CLASS 2>/dev/null`).Output()
	fg.App = lastQuoted(string(classOut))

	return fg, nil
}

// extractXpropString pulls the value out of a line like:
//
//	_NET_WM_NAME(UTF8_STRING) = "Some Title"
func extractXpropString(s string) string {
	i := strings.Index(s, "= ")
	if i < 0 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(s[i+2:]), `"`)
}

// lastQuoted returns the last double-quoted token on the line (WM_CLASS lists
// instance and class; the class is last and is the better app label).
func lastQuoted(s string) string {
	parts := strings.Split(s, `"`)
	// parts: [prefix, a, sep, b, trailing] -> quoted tokens are odd indices.
	last := ""
	for i := 1; i < len(parts); i += 2 {
		last = parts[i]
	}
	return last
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// linuxIdle reads idle time from `xprintidle` (milliseconds) if available.
type linuxIdle struct{}

func NewIdle() IdleReporter { return linuxIdle{} }

func (linuxIdle) IdleFor() (time.Duration, error) {
	out, err := exec.Command("xprintidle").Output()
	if err != nil {
		return 0, err
	}
	ms, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(ms) * time.Millisecond, nil
}
