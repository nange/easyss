//go:build !windows && !without_tray

package main

import "github.com/nange/systray"

func (a *TrayApp) addUWPLoopbackMenu(root *systray.Menu) {
	// No-op on non-Windows
}
