//go:build !with_notray

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/getlantern/systray"
	"github.com/nange/easyss"
	log "github.com/sirupsen/logrus"
)

func StartEasyss(ss *easyss.Easyss) {
	pac := NewPAC(ss.LocalPort(), ss.LocalPacPort(), ss.BindAll())
	st := NewSysTray(ss, pac)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Kill, os.Interrupt, syscall.SIGINT, syscall.SIGTERM,
			syscall.SIGQUIT)

		select {
		case sig := <-c:
			log.Infof("got signal to exit: %v", sig)
			st.CloseService()
			os.Exit(0)
		case <-st.closing:
			log.Infof("easyss exiting...")
		}
	}()

	systray.Run(st.TrayReady, st.Exit) // system tray management
}
