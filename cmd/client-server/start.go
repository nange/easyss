// +build !mips,!mipsle,!mips64,!mips64le

package main

import (
	"github.com/getlantern/systray"
	"github.com/nange/easyss"
)

func StartEasyss(ss *easyss.Easyss) {
	systray.Run(ss.TrayReady, ss.TrayExit) // system tray management
}
