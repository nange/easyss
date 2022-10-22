//go:build !with_notray

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/getlantern/systray"
	"github.com/nange/easyss"
	log "github.com/sirupsen/logrus"
)

const PacPath = "/proxy.pac"

func StartEasyss(ss *easyss.Easyss) {
	url := fmt.Sprintf("http://localhost:%d%s", ss.LocalPort()+1, PacPath)
	pac := NewPAC(ss.LocalPort(), PacPath, url, ss.BindAll())
	st := NewSysTray(ss, pac)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Kill, os.Interrupt, syscall.SIGINT, syscall.SIGTERM,
			syscall.SIGQUIT)

		select {
		case <-c:
			log.Infof("got signal to exit: %v", <-c)
			st.CloseService()
		case <-st.closing:
			log.Infof("easyss exiting...")
		}
		os.Exit(0)
	}()

	systray.Run(st.TrayReady, st.Exit) // system tray management
}
