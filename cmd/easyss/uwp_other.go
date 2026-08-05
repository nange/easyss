//go:build !windows && !headless

package main

func (a *TrayApp) addUWPLoopbackMenu() {
	// No-op on non-Windows
}
