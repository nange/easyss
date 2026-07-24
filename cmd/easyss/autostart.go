//go:build !without_tray

package main

// EnableAutoStart registers the app to start at user login.
func EnableAutoStart() error {
	return enableAutoStart()
}

// DisableAutoStart unregisters the app from starting at user login.
func DisableAutoStart() error {
	return disableAutoStart()
}

// IsAutoStartEnabled checks whether the app is registered to start at login.
func IsAutoStartEnabled() bool {
	return isAutoStartEnabled()
}
