package main

import (
	"os"

	"github.com/getlantern/systray"
	"github.com/nange/easyss/icon"
	log "github.com/sirupsen/logrus"
)

type Tray struct {
	pacChan chan<- PACStatus
}

func NewTray(pacChan chan<- PACStatus) *Tray {
	return &Tray{
		pacChan: pacChan,
	}
}

func (t *Tray) Run() {
	systray.Run(t.onReady, t.onExit)
}

func (t *Tray) onReady() {
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

				t.pacChan <- PACOFF
			} else {
				cPAC.Check()
				cGlobal.Enable()

				t.pacChan <- PACON
			}
			log.Infof("pac btn clicked...is checked:%v", cPAC.Checked())
		case <-cGlobal.ClickedCh:
			if cGlobal.Disabled() {
				break
			}
			if cGlobal.Checked() {
				cGlobal.Uncheck()
				t.pacChan <- PACOFFGLOBAL
			} else {
				cGlobal.Check()
				t.pacChan <- PACONGLOBAL
			}
			log.Infof("global btn clicked... is checked:%v", cGlobal.Checked())
		case <-cQuit.ClickedCh:
			log.Infof("quit btn clicked quit now...")
			systray.Quit()
			os.Exit(0)
		}
	}
}

func (t *Tray) onExit() {
	log.Info("easyss exited...")
}

