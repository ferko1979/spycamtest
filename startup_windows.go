//go:build windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const startupName = "SpyCamAgent"

func startupIsEnabled() (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.QUERY_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()

	_, _, err = k.GetStringValue(startupName)
	if err == nil {
		return true, nil
	}
	return false, nil
}

func startupEnable() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)

	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	// Quote path in case of spaces
	return k.SetStringValue(startupName, `"`+exe+`"`)
}

func startupDisable() error {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	_ = k.DeleteValue(startupName)
	return nil
}