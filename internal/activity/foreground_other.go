//go:build !windows && !darwin && !linux

package activity

import (
	"errors"
	"time"
)

// unsupportedSampler is used on platforms without a foreground-window
// implementation. It returns an error so the tracker records nothing.
type unsupportedSampler struct{}

func NewSampler() Sampler { return unsupportedSampler{} }

func (unsupportedSampler) Foreground() (Foreground, error) {
	return Foreground{}, errors.New("activity tracking not supported on this platform")
}

// TitleCapability reports that tracking is unsupported on this platform.
func TitleCapability() (bool, string) {
	return false, "Activity tracking is not supported on this platform."
}

// OpenPermissionSettings is a no-op on unsupported platforms.
func OpenPermissionSettings() error { return nil }

// NewIdle returns a no-op idle reporter on unsupported platforms.
func NewIdle() IdleReporter { return noIdle{} }

type noIdle struct{}

func (noIdle) IdleFor() (time.Duration, error) { return 0, nil }
