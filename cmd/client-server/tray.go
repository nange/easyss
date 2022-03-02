//go:build with_tray

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/getlantern/systray"
	"github.com/nange/easyss"
	"github.com/nange/easyss/icon"
	"github.com/nange/easyss/util"
	log "github.com/sirupsen/logrus"
)

type SysTray struct {
	ss  *easyss.Easyss
	pac *PAC
}

func NewSysTray(ss *easyss.Easyss, pac *PAC) *SysTray {
	return &SysTray{
		ss:  ss,
		pac: pac,
	}
}

func (st *SysTray) TrayReady() {
	if err := st.ss.InitTcpPool(); err != nil {
		log.Errorf("init tcp pool error:%v", err)
	}
	go st.pac.SysPAC()   // system pac configuration
	go st.ss.Local()     // start local server
	go st.ss.HttpLocal() // start local http proxy server

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Kill, os.Interrupt, syscall.SIGINT, syscall.SIGTERM,
			syscall.SIGQUIT)
		log.Infof("got signal to exit: %v", <-c)
		st.TrayExit()
	}()

	systray.SetIcon(icon.Data)
	systray.SetTitle("Easyss")
	systray.SetTooltip("Easyss")

	cPAC := systray.AddMenuItem("启用PAC(自动代理)", "启用PAC")
	systray.AddSeparator()
	cPAC.Check() // checked as default
	cGlobal := systray.AddMenuItem("全局代理模式", "全局模式")
	systray.AddSeparator()
	cCatLog := systray.AddMenuItem("查看Easyss运行日志", "查看日志")
	systray.AddSeparator()
	cQuit := systray.AddMenuItem("退出", "退出Easyss APP")

	for {
		select {
		case <-cPAC.ClickedCh:
			if cPAC.Checked() {
				cPAC.Uncheck()

				cGlobal.Uncheck()
				cGlobal.Disable()

				st.pac.ch <- PACOFF
			} else {
				cPAC.Check()
				cGlobal.Enable()

				st.pac.ch <- PACON
			}
			log.Infof("pac btn clicked...is checked:%v", cPAC.Checked())
		case <-cGlobal.ClickedCh:
			if cGlobal.Disabled() {
				break
			}
			if cGlobal.Checked() {
				cGlobal.Uncheck()
				if cPAC.Checked() {
					st.pac.ch <- PACON
				} else {
					st.pac.ch <- PACOFFGLOBAL
				}
			} else {
				cGlobal.Check()
				st.pac.ch <- PACONGLOBAL
			}
			log.Infof("global btn clicked... is checked:%v", cGlobal.Checked())
		case <-cCatLog.ClickedCh:
			log.Infof("cat log btn clicked...")
			if err := st.catLog(); err != nil {
				log.Errorf("cat log err:%v", err)
			}

		case <-cQuit.ClickedCh:
			log.Infof("quit btn clicked quit now...")
			systray.Quit()
			st.TrayExit() // on linux there have some bugs, we should invoke trayExit() again
		}
	}
}

func (st *SysTray) catLog() error {
	win := `-FilePath powershell  -WorkingDirectory "%s" -ArgumentList "-Command Get-Content %s -Wait %s"`
	if runtime.GOOS == "windows" && util.SysSupportPowershell() {
		if util.SysPowershellMajorVersion() >= 3 {
			win = fmt.Sprintf(win, util.GetCurrentDir(), st.ss.GetLogFileFullPathName(), "-Tail 100")
		} else {
			win = fmt.Sprintf(win, util.GetCurrentDir(), st.ss.GetLogFileFullPathName(), "-ReadCount 100")
		}
	}

	cmdmap := map[string][]string{
		"windows": {"powershell", "-Command", "Start-Process", win},
		"linux":   {"x-terminal-emulator", "-e", "tail", "-50f", st.ss.GetLogFileFullPathName()},
		"darwin":  {"open", "-a", "Console", st.ss.GetLogFileFullPathName()},
	}
	cmd := exec.Command(cmdmap[runtime.GOOS][0], cmdmap[runtime.GOOS][1:]...)
	return cmd.Start()
}

func (st *SysTray) TrayExit() {
	st.pac.ch <- PACOFF
	st.ss.Close()
	time.Sleep(time.Second) // ensure the pac settings to default value
	log.Info("easyss exited...")
	os.Exit(0)
}
