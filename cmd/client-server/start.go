//go:build !with_notray

package main

import (
	"fmt"

	"github.com/getlantern/systray"
	"github.com/nange/easyss"
)

const PacPath = "/proxy.pac"

func StartEasyss(ss *easyss.Easyss) {
	url := fmt.Sprintf("http://localhost:%d%s", ss.LocalPort()+1, PacPath)
	pac := NewPAC(ss.LocalPort(), PacPath, url, ss.BindAll())
	st := NewSysTray(ss, pac)
	systray.Run(st.TrayReady, st.TrayExit) // system tray management
}
