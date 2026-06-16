//go:build !windows && !without_tray

package main

func (a *TrayApp) addUWPLoopbackMenu() {
	// No-op on non-Windows
}
