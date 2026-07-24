//go:build !windows && !darwin && !linux && !without_tray

package main

// On unsupported platforms, auto-start is a no-op. The tray menu item
// still appears but is disabled (always unchecked and non-functional).

func enableAutoStart() error {
	return nil
}

func disableAutoStart() error {
	return nil
}

func isAutoStartEnabled() bool {
	return false
}
