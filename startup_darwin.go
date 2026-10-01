//go:build darwin

package main

import (
	"os"
	"path/filepath"
)

const launchAgentID = "com.spycam.agent"

func startupIsEnabled() (bool, error) {
	p, err := launchAgentPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	return err == nil, nil
}

func startupEnable() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)

	p, err := launchAgentPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}

	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
 <dict>
  <key>Label</key><string>` + launchAgentID + `</string>
  <key>ProgramArguments</key>
  <array>
   <string>` + exe + `</string>
  </array>
  <key>RunAtLoad</key><true/>
 </dict>
</plist>
`
	return os.WriteFile(p, []byte(plist), 0644)
}

func startupDisable() error {
	p, err := launchAgentPath()
	if err != nil {
		return err
	}
	_ = os.Remove(p)
	return nil
}

func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentID+".plist"), nil
}
