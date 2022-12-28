//go:build !with_notray

package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"sync"

	"github.com/getlantern/systray"
	"github.com/nange/easyss"
	"github.com/nange/easyss/icon"
	"github.com/nange/easyss/util"
	log "github.com/sirupsen/logrus"
)

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

	st.AddSelectServerMenu()
	systray.AddSeparator()

	st.AddProxyRuleMenu()
	systray.AddSeparator()

	_, tun2socksMenu := st.AddProxyObjectMenu()
	systray.AddSeparator()
	st.SetTun2socksMenu(tun2socksMenu)

	st.AddCatLogsMenu()
	systray.AddSeparator()

	st.AddExitMenu()

	st.StartLocalService()
}

func (st *SysTray) AddSelectServerMenu() {
	selectServer := systray.AddMenuItem("选择服务器", "请选择")

	var subMenuItems []*systray.MenuItem
	addrs := st.SS().ServerListAddrs()
	if len(addrs) > 0 {
		for _, addr := range addrs {
			item := selectServer.AddSubMenuItemCheckbox(addr, "服务器地址", false)
			subMenuItems = append(subMenuItems, item)
		}
	} else {
		item := selectServer.AddSubMenuItemCheckbox(st.SS().ServerAddr(), "服务器地址", false)
		subMenuItems = append(subMenuItems, item)
	}
	subMenuItems[0].Check()

	for i, item := range subMenuItems {
		go func(_i int, _item *systray.MenuItem) {
			for {
				select {
				case <-_item.ClickedCh:
					func() {
						if _item.Checked() {
							return
						}
						log.Infof("changing server to:%s", addrs[_i])
						for _, v := range subMenuItems {
							v.Uncheck()
						}

						config := st.SS().ConfigClone()
						serverConfig := st.SS().ServerList()[_i]
						config.Server = serverConfig.Server
						config.ServerPort = serverConfig.ServerPort
						config.Password = serverConfig.Password
						config.DisableUTLS = serverConfig.DisableUTLS
						if err := st.RestartService(config); err != nil {
							log.Errorf("changing server to:%s err:%v", addrs[_i], err)
						} else {
							_item.Check()
							log.Infof("changes server to:%s success", addrs[_i])
						}
					}()
				}
			}

		}(i, item)
	}
}

func (st *SysTray) AddProxyRuleMenu() (*systray.MenuItem, *systray.MenuItem, *systray.MenuItem) {
	proxyMenue := systray.AddMenuItem("代理规则", "请选择")

	auto := proxyMenue.AddSubMenuItemCheckbox("自动(自定义规则+绕过大陆IP域名)", "自动判断请求是否走代理", false)
	if st.SS().ProxyRule() == easyss.ProxyRuleAuto {
		auto.Check()
	}
	proxy := proxyMenue.AddSubMenuItemCheckbox("代理全部", "代理所有地址的请求", false)
	if st.SS().ProxyRule() == easyss.ProxyRuleProxy {
		proxy.Check()
	}
	direct := proxyMenue.AddSubMenuItemCheckbox("直接连接", "所有请求直接连接，不走代理", false)
	if st.SS().ProxyRule() == easyss.ProxyRuleDirect {
		direct.Check()
	}

	go func() {
		for {
			select {
			case <-auto.ClickedCh:
				if auto.Checked() {
					continue
				}
				st.SS().SetProxyRule(easyss.ProxyRuleAuto)
				auto.Check()
				proxy.Uncheck()
				direct.Uncheck()
			case <-proxy.ClickedCh:
				if proxy.Checked() {
					continue
				}
				st.SS().SetProxyRule(easyss.ProxyRuleProxy)
				proxy.Check()
				auto.Uncheck()
				direct.Uncheck()
			case <-direct.ClickedCh:
				if direct.Checked() {
					continue
				}
				st.SS().SetProxyRule(easyss.ProxyRuleDirect)
				direct.Check()
				auto.Uncheck()
				proxy.Uncheck()
			}
		}
	}()

	return auto, proxy, direct
}

func (st *SysTray) AddProxyObjectMenu() (*systray.MenuItem, *systray.MenuItem) {
	proxyMenue := systray.AddMenuItem("代理对象", "请选择")

	browser := proxyMenue.AddSubMenuItemCheckbox("浏览器(设置系统代理)", "设置系统代理配置", true)
	global := proxyMenue.AddSubMenuItemCheckbox("系统全局流量(Tun2socks)", "Tun2socks代理系统全局", false)

	go func() {
		for {
			select {
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

	return browser, global
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

	if ss.EnabledTun2socksFromConfig() {
		if err := st.ss.CreateTun2socks(); err != nil {
			log.Fatalf("create tun2socks err:%s", err.Error())
		} else {
			st.tun2socksMenu.Check()
		}
	}
}

func (st *SysTray) RestartService(config *easyss.Config) error {
	st.CloseService()
	st.Tun2socksMenu().Uncheck()

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

func (st *SysTray) SetTun2socksMenu(t *systray.MenuItem) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.tun2socksMenu = t
}

func (st *SysTray) Tun2socksMenu() *systray.MenuItem {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.tun2socksMenu
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
