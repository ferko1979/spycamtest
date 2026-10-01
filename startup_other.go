//go:build !windows && !darwin

package main

func startupIsEnabled() (bool, error) { return false, nil }
func startupEnable() error            { return nil }
func startupDisable() error           { return nil }
