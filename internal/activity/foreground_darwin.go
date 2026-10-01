//go:build darwin

package activity

import (
	"os/exec"
	"strings"
	"time"
)

// macSampler reads the frontmost application name and its window title via
// AppleScript (osascript). Reading the window title requires the user to
// grant Accessibility permission to the app in System Settings → Privacy &
// Security → Accessibility; this is an OS-level, user-visible consent gate.
// If permission is not granted, the title comes back empty and only the app
// name is recorded.
type macSampler struct{}

func NewSampler() Sampler { return macSampler{} }

const frontmostScript = `
global frontApp, frontTitle
set frontApp to ""
set frontTitle to ""
tell application "System Events"
	set frontApp to name of first application process whose frontmost is true
	try
		tell process frontApp
			set frontTitle to name of front window
		end try
	end try
end tell
return frontApp & "\n" & frontTitle
`

func (macSampler) Foreground() (Foreground, error) {
	out, err := exec.Command("osascript", "-e", frontmostScript).Output()
	if err != nil {
		return Foreground{}, err
	}
	parts := strings.SplitN(strings.TrimRight(string(out), "\n"), "\n", 2)
	fg := Foreground{}
	if len(parts) > 0 {
		fg.App = strings.TrimSpace(parts[0])
	}
	if len(parts) > 1 {
		fg.Title = strings.TrimSpace(parts[1])
	}
	return fg, nil
}

// TitleCapability reports whether window titles can be read. On macOS this
// requires Accessibility permission; we probe by running the frontmost
// script and treating an error as "permission not granted".
func TitleCapability() (bool, string) {
	if _, err := exec.Command("osascript", "-e", frontmostScript).CombinedOutput(); err != nil {
		return false, "Grant Accessibility permission: System Settings → Privacy & Security → Accessibility, then enable SpyCam Agent. Until then only time totals (not app/title) are recorded."
	}
	return true, ""
}

// OpenPermissionSettings opens the macOS Accessibility settings pane so the
// user can grant permission.
func OpenPermissionSettings() error {
	return exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility").Start()
}

// macIdle reads the HID idle time via `ioreg`. Best-effort; returns 0 if it
// cannot be determined.
type macIdle struct{}

func NewIdle() IdleReporter { return macIdle{} }

func (macIdle) IdleFor() (time.Duration, error) {
	out, err := exec.Command("sh", "-lc",
		`ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print $NF; exit}'`).Output()
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return 0, nil
	}
	// Value is in nanoseconds.
	ns, perr := parseUint(s)
	if perr != nil {
		return 0, perr
	}
	return time.Duration(ns) * time.Nanosecond, nil
}
