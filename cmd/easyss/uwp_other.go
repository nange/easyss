//go:build !windows && !headless

package main

import "github.com/gogpu/systray"

// uwpMenu 在非 Windows 上没有状态，install 是空操作；buildTray 因此不必区分平台。
type uwpMenu struct{}

func (*uwpMenu) install(*systray.Menu, func()) {}
