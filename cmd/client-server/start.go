//go:build with_tray

package main

import (
	"fmt"

	"github.com/getlantern/systray"
	"github.com/nange/easyss"
)

func StartEasyss(ss *easyss.Easyss) {
	url := fmt.Sprintf("http://localhost:%d%s", ss.LocalPort()+1, PacPath)
	gurl := fmt.Sprintf("http://localhost:%d%s?global=true", ss.LocalPort()+1, PacPath)
	pac := NewPAC(ss.LocalPort(), PacPath, url, gurl)
	st := NewSysTray(ss, pac)
	systray.Run(st.TrayReady, st.TrayExit) // system tray management
}
