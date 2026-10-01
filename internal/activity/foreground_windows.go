//go:build windows

package activity

import (
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                   = windows.NewLazySystemDLL("user32.dll")
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetForegroundWindow  = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW       = user32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW = user32.NewProc("GetWindowTextLengthW")
	procGetWindowThreadPID   = user32.NewProc("GetWindowThreadProcessId")
	procGetLastInputInfo     = user32.NewProc("GetLastInputInfo")
	procGetTickCount         = kernel32.NewProc("GetTickCount")
)

// WinSampler reads the active window title and owning process name using the
// Win32 API. It reads only the title and executable name — not window
// contents, keystrokes, or anything else.
type WinSampler struct{}

func NewSampler() Sampler { return WinSampler{} }

func (WinSampler) Foreground() (Foreground, error) {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return Foreground{}, nil
	}

	// Window title.
	n, _, _ := procGetWindowTextLengthW.Call(hwnd)
	title := ""
	if int(n) > 0 {
		buf := make([]uint16, int(n)+1)
		procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		title = syscall.UTF16ToString(buf)
	}

	// Owning process -> executable base name.
	var pid uint32
	procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	app := ""
	if pid != 0 {
		if name, err := processName(pid); err == nil {
			app = name
		}
	}

	return Foreground{App: app, Title: title}, nil
}

func processName(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	full := syscall.UTF16ToString(buf[:size])
	return filepath.Base(full), nil
}

// TitleCapability reports whether window titles can be read. On Windows this
// requires no extra permission.
func TitleCapability() (bool, string) { return true, "" }

// OpenPermissionSettings is a no-op on Windows (no permission needed).
func OpenPermissionSettings() error { return nil }

// WinIdle implements IdleReporter via GetLastInputInfo.
type WinIdle struct{}

func NewIdle() IdleReporter { return WinIdle{} }

type lastInputInfo struct {
	cbSize uint32
	dwTime uint32
}

func (WinIdle) IdleFor() (time.Duration, error) {
	var lii lastInputInfo
	lii.cbSize = uint32(unsafe.Sizeof(lii))
	r, _, err := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	if r == 0 {
		return 0, err
	}
	tick, _, _ := procGetTickCount.Call()
	ms := uint32(tick) - lii.dwTime
	return time.Duration(ms) * time.Millisecond, nil
}
