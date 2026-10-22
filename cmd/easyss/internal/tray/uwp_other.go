//go:build !windows && !headless

package tray

import "github.com/gogpu/systray"

// UWP 在非 Windows 上没有状态，install/startRefresh 是空操作；buildTray 因此不必区分平台。
type UWP struct{}

func (*UWP) Install(*systray.Menu, func()) {}

func (*UWP) StartRefresh() {}
