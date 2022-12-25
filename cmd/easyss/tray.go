//go:build !with_notray

package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"sync"

	"github.com/getlantern/systray"
	"github.com/nange/easyss"
	"github.com/nange/easyss/icon"
	"github.com/nange/easyss/util"
	log "github.com/sirupsen/logrus"
)

type menu struct {
	Title   string
	Tips    string
	OnClick func(m *systray.MenuItem)
}

type SysTray struct {
	ss      *easyss.Easyss
	pac     *PAC
	closing chan struct{}
	mu      *sync.RWMutex

	tun2socksMenu *systray.MenuItem
}

func NewSysTray(ss *easyss.Easyss, pac *PAC) *SysTray {
	return &SysTray{
		ss:      ss,
		pac:     pac,
		closing: make(chan struct{}, 1),
		mu:      &sync.RWMutex{},
	}
}

func (st *SysTray) TrayReady() {
	systray.SetTemplateIcon(icon.Data, icon.Data)
	systray.SetTooltip("Easyss")

	st.StartLocalService()

	st.AddSelectConfMenu()
	systray.AddSeparator()

	_, _, tun2socksMenu := st.AddProxyOptsMenu()
	systray.AddSeparator()
	st.tun2socksMenu = tun2socksMenu

	st.AddCatLogsMenu()
	systray.AddSeparator()

	st.AddExitMenu()
}

func (st *SysTray) AddSelectConfMenu() *systray.MenuItem {
	selectConf := systray.AddMenuItem("选择配置", "请选择")

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
					log.Infof("changing config to: %v", fileName)
					config, err := easyss.ParseConfig(fileName)
					if err != nil {
						log.Errorf("parse config file:%v", err)
					}
					if err := st.RestartService(config); err != nil {
						log.Errorf("restarting systray err:%v", err)
					}
				},
			})
		}
	} else {
		log.Errorf("read file list err:%v", err)
	}

	var miArr []*systray.MenuItem
	st.mu.RLock()
	configFilename := st.ss.ConfigFilename()
	st.mu.RUnlock()
	for _, v := range confList {
		mi := selectConf.AddSubMenuItemCheckbox(v.Title, v.Title, v.Title == configFilename)
		_v := v
		miArr = append(miArr, mi)
		go func() {
			for {
				select {
				case <-mi.ClickedCh:
					for _, m := range miArr {
						m.Uncheck()
					}
					mi.Check()
					_v.OnClick(mi)
				}
			}
		}()
	}

	return selectConf
}

func (st *SysTray) AddProxyOptsMenu() (*systray.MenuItem, *systray.MenuItem, *systray.MenuItem) {
	proxyMenue := systray.AddMenuItem("代理选项", "请选择")

	auto := proxyMenue.AddSubMenuItemCheckbox("自动(绕过大陆IP域名)", "自动判断请求是否走代理", true)
	browser := proxyMenue.AddSubMenuItemCheckbox("代理浏览器", "浏览器模式", true)
	global := proxyMenue.AddSubMenuItemCheckbox("代理系统全局流量", "系统全局模式", false)

	go func() {
		for {
			select {
			case <-auto.ClickedCh:
				if auto.Checked() {
					st.SS().SetAutoProxy(false)
					auto.Uncheck()
				} else {
					st.SS().SetAutoProxy(true)
					auto.Check()
				}
			case <-browser.ClickedCh:
				if browser.Checked() {
					if err := st.PAC().PACOff(); err != nil {
						log.Errorf("pac off err:%s", err.Error())
						continue
					}
					browser.Uncheck()
				} else {
					if err := st.PAC().PACOn(); err != nil {
						log.Errorf("pac on err:%s", err.Error())
						continue
					}
					browser.Check()
				}
			case <-global.ClickedCh:
				if global.Checked() {
					if err := st.SS().CloseTun2socks(); err != nil {
						log.Errorf("close tun2socks err:%s", err.Error())
						continue
					}
					global.Uncheck()
				} else {
					if err := st.ss.CreateTun2socks(); err != nil {
						log.Errorf("create tun2socks err:%s", err.Error())
						continue
					}
					global.Check()
				}
			}
		}
	}()

	return auto, browser, global
}

func (st *SysTray) AddCatLogsMenu() *systray.MenuItem {
	catLog := systray.AddMenuItem("查看运行日志", "查看日志")

	go func() {
		for {
			select {
			case <-catLog.ClickedCh:
				log.Debugf("cat log btn clicked...")
				if err := st.catLog(); err != nil {
					log.Errorf("cat log err:%v", err)
				}
			}
		}
	}()

	return catLog
}

func (st *SysTray) AddExitMenu() *systray.MenuItem {
	quit := systray.AddMenuItem("退出", "退出Easyss APP")

	go func() {
		for {
			select {
			case <-quit.ClickedCh:
				log.Debugf("exit btn clicked quit now...")
				systray.Quit()
			}
		}
	}()

	return quit
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

	cmdMap := map[string][]string{
		"windows": {"powershell", "-Command", "Start-Process", win},
		"linux":   {"x-terminal-emulator", "-e", "tail", "-50f", util.LogFilePath()},
		"darwin":  {"open", "-a", "Console", util.LogFilePath()},
	}
	cmd := exec.Command(cmdMap[runtime.GOOS][0], cmdMap[runtime.GOOS][1:]...)
	return cmd.Start()
}

func (st *SysTray) CloseService() {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.pac.Close()
	st.ss.Close()
}

func (st *SysTray) Exit() {
	st.closing <- struct{}{}
	st.CloseService()
	log.Info("systray exiting...")
}

func (st *SysTray) StartLocalService() {
	st.mu.RLock()
	defer st.mu.RUnlock()
	ss := st.ss
	pac := st.pac

	if err := ss.InitTcpPool(); err != nil {
		log.Errorf("init tcp pool error:%v", err)
	}

	go pac.LocalPAC()   // system pac configuration
	go ss.LocalSocks5() // start local server
	go ss.LocalHttp()   // start local http proxy server
	if ss.EnableForwardDNS() {
		go ss.LocalDNSForward() // start local dns forward server
	}

	if ss.EnabledTun2socks() {
		if err := st.ss.CreateTun2socks(); err != nil {
			log.Fatalf("create tun2socks err:%s", err.Error())
		}
	}
}

func (st *SysTray) RestartService(config *easyss.Config) error {
	st.CloseService()
	st.tun2socksMenu.Uncheck()

	ss, err := easyss.New(config)
	if err != nil {
		return err
	}
	pac := NewPAC(ss.LocalPort(), ss.LocalPacPort(), ss.BindAll())

	st.SetSS(ss)
	st.SetPAC(pac)

	st.StartLocalService()

	return nil
}

func (st *SysTray) SetSS(ss *easyss.Easyss) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.ss = ss
}

func (st *SysTray) SS() *easyss.Easyss {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.ss
}

func (st *SysTray) SetPAC(pac *PAC) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pac = pac
}

func (st *SysTray) PAC() *PAC {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.pac
}
