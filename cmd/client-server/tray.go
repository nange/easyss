//go:build !with_notray

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
	"regexp"
)

type menu struct {
	Title   string
	Tips    string
	Icon    []byte
	OnClick func(m *systray.MenuItem)
}

func addRadioMenu(title string, defaultTitle string, sub []*menu) {
	boot := systray.AddMenuItem(title, "")
	var miArr []*systray.MenuItem
	for i, v := range sub {
		mi := boot.AddSubMenuItemCheckbox(v.Title, v.Title, v.Title == defaultTitle)
		_v := v
		_i := i
		miArr = append(miArr, mi)
		go func() {
			for {
				select {
				case <-mi.ClickedCh:
					_v.OnClick(mi)
					for j, e := range miArr {
						if j == _i {
							e.Check()
						} else {
							e.Uncheck()
						}
					}
				}
			}
		}()
	}
}



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

	systray.SetTemplateIcon(icon.Data, icon.Data)
//    systray.SetTitle("Easyss")
	systray.SetTooltip("Easyss")
	
	startProxy := func() {
		log.Debugf("current server: %s", st.ss.Server())
		if err := st.ss.InitTcpPool(); err != nil {
			log.Errorf("init tcp pool error:%v", err)
		}
		go st.ss.Local()     // start local server
		go st.ss.HttpLocal() // start local http proxy server
	}

	closeProxy := func() {
		st.ss.Close()
	}

	updateProxyConfig  := func(fileName string) {
		var cmdConfig easyss.Config
		config, err := easyss.ParseConfig(fileName)
		if err != nil {
			config = &cmdConfig
		} else {
			easyss.UpdateConfig(config, &cmdConfig)
		}

		if config.Password == "" || config.Server == "" || config.ServerPort == 0 {
			log.Fatalln("server address, server port and password should not empty")
		}

		st.ss.UpdateConfig(config)
	}

	restartProxy := func() {
		closeProxy()
		startProxy()
	}

	var confList []*menu
	var ConfDir = util.CurrentDir()
	var confFileReg = regexp.MustCompile(`^config(\S+)?.json$`)
	if files, err := util.DirFileList(ConfDir); err == nil {
		for _, v := range files {
			fileName := v
			if confFileReg.MatchString(fileName) == false {
				continue
			}
			confList = append(confList, &menu{
				Title: fileName,
				OnClick: func(m *systray.MenuItem) {
					log.Debugf("change config: %v", fileName)
					updateProxyConfig(fileName)
					restartProxy()
				},
			})
		}
	}
	
	addRadioMenu("选择配置", "config.json", confList)
	systray.AddSeparator()

	cPAC := systray.AddMenuItemCheckbox("启用PAC(自动代理)", "启用PAC", false)
	systray.AddSeparator()
	cGlobal := systray.AddMenuItemCheckbox("全局代理模式", "全局模式", false)
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
			log.Debugf("pac btn clicked...is checked:%v", cPAC.Checked())
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
			log.Debugf("global btn clicked... is checked:%v", cGlobal.Checked())
		case <-cCatLog.ClickedCh:
			log.Debugf("cat log btn clicked...")
			if err := st.catLog(); err != nil {
				log.Errorf("cat log err:%v", err)
			}

		case <-cQuit.ClickedCh:
			log.Debugf("quit btn clicked quit now...")
			systray.Quit()
			st.TrayExit() // on linux there have some bugs, we should invoke trayExit() again
		}
	}
}

func (st *SysTray) catLog() error {
	win := `-FilePath powershell  -WorkingDirectory "%s" -ArgumentList "-Command Get-Content %s -Wait %s"`
	if runtime.GOOS == "windows" && util.SysSupportPowershell() {
		if util.SysPowershellMajorVersion() >= 3 {
			win = fmt.Sprintf(win, util.CurrentDir(), util.LogFilePath(), "-Tail 100")
		} else {
			win = fmt.Sprintf(win, util.CurrentDir(), util.LogFilePath(), "-ReadCount 100")
		}
	}

	cmdmap := map[string][]string{
		"windows": {"powershell", "-Command", "Start-Process", win},
		"linux":   {"x-terminal-emulator", "-e", "tail", "-50f", util.LogFilePath()},
		"darwin":  {"open", "-a", "Console", util.LogFilePath()},
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
