package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getlantern/systray"
	"github.com/nange/easyss/icon"
	log "github.com/sirupsen/logrus"
)

func (ss *Easyss) trayReady() {
	if err := ss.InitTcpPool(); err != nil {
		log.Fatalf("init tcp pool error:%v", err)
	}
	go ss.SysPAC() // system pac configuration
	go ss.Local()  // start local server
	if ss.config.EnableQuic {
		go ss.sessManage() // start quic session manage
	}

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Kill, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM,
			syscall.SIGQUIT)
		log.Infof("receive exit signal:%v", <-c)
		ss.trayExit()
	}()

	systray.SetIcon(icon.Data)
	systray.SetTitle("Easyss APP")
	systray.SetTooltip("Easyss")

	cPAC := systray.AddMenuItem("启用PAC", "启用PAC")
	cPAC.Check() // checked as default
	cGlobal := systray.AddMenuItem("全局模式", "全局模式")
	cQuit := systray.AddMenuItem("退出", "退出Easyss APP")

	for {
		select {
		case <-cPAC.ClickedCh:
			if cPAC.Checked() {
				cPAC.Uncheck()

				cGlobal.Uncheck()
				cGlobal.Disable()

				ss.pac.ch <- PACOFF
			} else {
				cPAC.Check()
				cGlobal.Enable()

				ss.pac.ch <- PACON
			}
			log.Infof("pac btn clicked...is checked:%v", cPAC.Checked())
		case <-cGlobal.ClickedCh:
			if cGlobal.Disabled() {
				break
			}
			if cGlobal.Checked() {
				cGlobal.Uncheck()
				ss.pac.ch <- PACOFFGLOBAL
			} else {
				cGlobal.Check()
				ss.pac.ch <- PACONGLOBAL
			}
			log.Infof("global btn clicked... is checked:%v", cGlobal.Checked())
		case <-cQuit.ClickedCh:
			log.Infof("quit btn clicked quit now...")
			systray.Quit()
		}
	}
}

func (ss *Easyss) trayExit() {
	ss.pac.ch <- PACOFF
	time.Sleep(time.Second) // ensure the pac settings to default value
	log.Info("easyss exited...")
	os.Exit(0)
}
