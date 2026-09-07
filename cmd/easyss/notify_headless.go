//go:build headless

package main

// notifyConfigError is a no-op in headless builds: there is no system
// tray to show a notification from, and the caller already logs the
// startup error.
func notifyConfigError(error) {}
