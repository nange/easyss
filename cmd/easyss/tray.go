//go:build !with_notray

package main

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/getlantern/systray"
	"github.com/nange/easyss/v2"
	"github.com/nange/easyss/v2/icon"
	"github.com/nange/easyss/v2/util"
	log "github.com/sirupsen/logrus"
)

type SysTray struct {
	ss      *easyss.Easyss
	closing chan struct{}
	mu      *sync.RWMutex

	browserMenu   *systray.MenuItem
	tun2socksMenu *systray.MenuItem
}

func NewSysTray(ss *easyss.Easyss) *SysTray {
	return &SysTray{
		ss:      ss,
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

	browserMenu, tun2socksMenu := st.AddProxyObjectMenu()
	systray.AddSeparator()
	st.SetBrowserMenu(browserMenu)
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
			if addr == st.SS().ServerAddr() {
				item.Check()
			}
		}
	} else {
		item := selectServer.AddSubMenuItemCheckbox(st.SS().ServerAddr(), "服务器地址", false)
		subMenuItems = append(subMenuItems, item)
		item.Check()
	}

	for i, item := range subMenuItems {
		go func(_i int, _item *systray.MenuItem) {
			for {
				select {
				case <-_item.ClickedCh:
					func() {
						if _item.Checked() {
							_item.Check()
							return
						}
						log.Infof("[SYSTRAY] changing server to:%s", addrs[_i])
						for _, v := range subMenuItems {
							v.Uncheck()
						}

						config := st.SS().ConfigClone()
						sc := st.SS().ServerList()[_i]
						sc.SetDefaultValue()
						config.OverrideFrom(&sc)
						if err := st.RestartService(config); err != nil {
							log.Errorf("[SYSTRAY] changing server to:%s err:%v", addrs[_i], err)
						} else {
							_item.Check()
							log.Infof("[SYSTRAY] changes server to:%s success", addrs[_i])
						}
					}()
				case <-st.closing:
					return
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

	browserChecked := true
	if st.SS().DisableSysProxy() {
		browserChecked = false
	}
	browser := proxyMenue.AddSubMenuItemCheckbox("浏览器(设置系统代理)", "设置系统代理配置", browserChecked)
	global := proxyMenue.AddSubMenuItemCheckbox("系统全局流量(Tun2socks)", "Tun2socks代理系统全局", false)

	go func() {
		for {
			select {
			case <-browser.ClickedCh:
				if browser.Checked() {
					if err := st.SS().SetSysProxyOffHTTP(); err != nil {
						log.Errorf("[SYSTRAY] set sys-proxy off http err:%s", err.Error())
						continue
					}
					browser.Uncheck()
				} else {
					if err := st.SS().SetSysProxyOnHTTP(); err != nil {
						log.Errorf("[SYSTRAY] set sys-proxy on http err:%s", err.Error())
						continue
					}
					browser.Check()
				}
			case <-global.ClickedCh:
				if global.Checked() {
					if err := st.SS().CloseTun2socks(); err != nil {
						log.Errorf("[SYSTRAY] close tun2socks err:%s", err.Error())
						continue
					}
					global.Uncheck()
				} else {
					if err := st.ss.CreateTun2socks(); err != nil {
						log.Errorf("[SYSTRAY] create tun2socks err:%s", err.Error())
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
				if err := st.catLog(); err != nil {
					log.Errorf("[SYSTRAY] cat log err:%v", err)
				}
			case <-st.closing:
				return
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
				systray.Quit()
			case <-st.closing:
				return
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
	_, err := util.Command(cmdMap[runtime.GOOS][0], cmdMap[runtime.GOOS][1:]...)
	return err
}

func (st *SysTray) CloseService() {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.browserMenu.Checked() {
		if err := st.ss.SetSysProxyOffHTTP(); err != nil {
			log.Errorf("[SYSTRAY] close service: set sysproxy off http: %s", err.Error())
		}
	}
	if err := st.ss.Close(); err != nil {
		log.Errorf("[SYSTRAY] close service: close easyss: %s", err.Error())
	}
}

func (st *SysTray) Exit() {
	st.closing <- struct{}{}
	st.CloseService()
	log.Info("[SYSTRAY] systray exiting...")
}

func (st *SysTray) StartLocalService() {
	st.mu.RLock()
	defer st.mu.RUnlock()
	ss := st.ss

	if err := ss.InitTcpPool(); err != nil {
		log.Errorf("[SYSTRAY] init tcp pool error:%v", err)
	}

	go ss.LocalSocks5() // start local server
	go ss.LocalHttp()   // start local http proxy server
	if ss.EnableForwardDNS() {
		go ss.LocalDNSForward() // start local dns forward server
	}

	if st.SysProxyIsOn() {
		if err := ss.SetSysProxyOnHTTP(); err != nil {
			log.Errorf("[SYSTRAY] set sys proxy on http err:%s", err.Error())
		}
	} else {
		if err := ss.SetSysProxyOffHTTP(); err != nil {
			log.Errorf("[SYSTRAY] set sys proxy off http err:%s", err.Error())
		}
	}

	if ss.EnabledTun2socksFromConfig() {
		if err := st.ss.CreateTun2socks(); err != nil {
			log.Fatalf("[SYSTRAY] create tun2socks err:%s", err.Error())
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

	st.SetSS(ss)

	st.StartLocalService()

	return nil
}

func (st *SysTray) SysProxyIsOn() bool {
	return st.BrowserMenu().Checked()
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

func (st *SysTray) SetBrowserMenu(b *systray.MenuItem) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.browserMenu = b
}

func (st *SysTray) BrowserMenu() *systray.MenuItem {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.browserMenu
}
