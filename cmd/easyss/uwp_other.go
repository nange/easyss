//go:build !windows && !headless

package main

import "github.com/gogpu/systray"

func (a *TrayApp) addUWPLoopbackMenu(root *systray.Menu) {
	// 在非 Windows 平台上为空操作
}
