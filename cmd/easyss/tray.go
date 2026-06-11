//go:build !without_tray

package main

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"sync"

	"github.com/getlantern/systray"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util"
)

type TrayApp struct {
	*App
	closing     chan struct{}
	mu          sync.RWMutex
	browserMenu *systray.MenuItem
	tunMenu     *systray.MenuItem
}

func (a *TrayApp) trayReady() {
	if err := a.Start(); err != nil {
		log.Error("[EASYSS-V3] tray start", "err", err)
		os.Exit(1)
	}

	systray.SetTemplateIcon(icon.Data, icon.Data)
	systray.SetTooltip("Easyss")

	a.addSelectServerMenu()
	systray.AddSeparator()

	a.addProxyRuleMenu()
	systray.AddSeparator()

	browserMenu, tunMenu := a.addProxyObjectMenu()
	systray.AddSeparator()
	a.SetBrowserMenu(browserMenu)
	a.SetTunMenu(tunMenu)

	a.addCatLogsMenu()
	systray.AddSeparator()

	a.addExitMenu()

	a.startLocalService()
}

func (a *TrayApp) trayExit() {
	select {
	case a.closing <- struct{}{}:
	default:
	}
	a.Stop()
	os.Exit(0)
}

func (a *TrayApp) addSelectServerMenu() {
	selectServer := systray.AddMenuItem("选择服务器", "请选择")

	addrs := a.cfg.ServerListAddrs()
	var subMenuItems []*systray.MenuItem

	if len(addrs) > 0 {
		for _, addr := range addrs {
			item := selectServer.AddSubMenuItemCheckbox(addr, "服务器地址", false)
			subMenuItems = append(subMenuItems, item)
			if addr == a.cfg.DefaultServerAddr() {
				item.Check()
			}
		}
	} else {
		item := selectServer.AddSubMenuItemCheckbox(a.cfg.DefaultServerAddr(), "服务器地址", false)
		subMenuItems = append(subMenuItems, item)
		item.Check()
	}

	for i, item := range subMenuItems {
		go func(idx int, mi *systray.MenuItem) {
			for {
				select {
				case <-mi.ClickedCh:
					func() {
						if mi.Checked() {
							mi.Check()
							return
						}
						addr := addrs[idx]
						log.Info("[SYSTRAY] changing server to", "addr", addr)
						for _, v := range subMenuItems {
							v.Uncheck()
						}
						clone := a.cfg.Clone()
						clone.SetDefaultServerIndex(idx)
						if err := a.restartService(clone); err != nil {
							log.Error("[SYSTRAY] changing server to", "addr", addr, "err", err)
						} else {
							mi.Check()
							log.Info("[SYSTRAY] changes server success to", "addr", addr)
						}
					}()
				case <-a.closing:
					return
				}
			}
		}(i, item)
	}
}

func (a *TrayApp) addProxyRuleMenu() {
	proxyMenu := systray.AddMenuItem("代理规则", "请选择")

	auto := proxyMenu.AddSubMenuItemCheckbox("自动(自定义规则+绕过大陆IP域名)", "自动判断请求是否走代理", false)
	if a.cfg.Routing.ProxyRule == "auto" {
		auto.Check()
	}

	autoBlock := proxyMenu.AddSubMenuItemCheckbox("自动+屏蔽广告跟踪", "自动判断请求是否走代理或者屏蔽", false)
	if a.cfg.Routing.ProxyRule == "auto_block" {
		autoBlock.Check()
	}

	reverseAuto := proxyMenu.AddSubMenuItemCheckbox("反向自动(国外访问国内)", "适用国外访问国内IP域名", false)
	if a.cfg.Routing.ProxyRule == "reverse_auto" {
		reverseAuto.Check()
	}

	proxy := proxyMenu.AddSubMenuItemCheckbox("代理全部(绕过局域网地址)", "代理除局域网地址的所有请求", false)
	if a.cfg.Routing.ProxyRule == "proxy" {
		proxy.Check()
	}

	direct := proxyMenu.AddSubMenuItemCheckbox("直接连接", "所有请求直接连接，不走代理", false)
	if a.cfg.Routing.ProxyRule == "direct" {
		direct.Check()
	}

	go func() {
		for {
			select {
			case <-auto.ClickedCh:
				if auto.Checked() {
					auto.Check()
					continue
				}
				a.setProxyRule("auto")
				auto.Check()
				autoBlock.Uncheck()
				reverseAuto.Uncheck()
				proxy.Uncheck()
				direct.Uncheck()
			case <-autoBlock.ClickedCh:
				if autoBlock.Checked() {
					autoBlock.Check()
					continue
				}
				a.setProxyRule("auto_block")
				autoBlock.Check()
				auto.Uncheck()
				reverseAuto.Uncheck()
				proxy.Uncheck()
				direct.Uncheck()
			case <-reverseAuto.ClickedCh:
				if reverseAuto.Checked() {
					reverseAuto.Check()
					continue
				}
				a.setProxyRule("reverse_auto")
				reverseAuto.Check()
				auto.Uncheck()
				autoBlock.Uncheck()
				proxy.Uncheck()
				direct.Uncheck()
			case <-proxy.ClickedCh:
				if proxy.Checked() {
					proxy.Check()
					continue
				}
				a.setProxyRule("proxy")
				proxy.Check()
				auto.Uncheck()
				autoBlock.Uncheck()
				reverseAuto.Uncheck()
				direct.Uncheck()
			case <-direct.ClickedCh:
				if direct.Checked() {
					direct.Check()
					continue
				}
				a.setProxyRule("direct")
				direct.Check()
				auto.Uncheck()
				autoBlock.Uncheck()
				reverseAuto.Uncheck()
				proxy.Uncheck()
			case <-a.closing:
				return
			}
		}
	}()
}

func (a *TrayApp) setProxyRule(rule string) {
	if a.cli != nil {
		a.cli.SetProxyRule(rule)
	}
	a.cfg.Routing.ProxyRule = rule
	log.Info("[SYSTRAY] proxy rule changed", "rule", rule)
}

func (a *TrayApp) addProxyObjectMenu() (*systray.MenuItem, *systray.MenuItem) {
	proxyMenu := systray.AddMenuItem("代理对象", "请选择")

	browserChecked := !a.cfg.Local.DisableSysProxy
	browser := proxyMenu.AddSubMenuItemCheckbox("浏览器(设置系统代理)", "设置系统代理配置", browserChecked)
	global := proxyMenu.AddSubMenuItemCheckbox("系统全局流量(Tun2socks)", "Tun2socks代理系统全局", a.cfg.Local.EnableTun2socks)

	go func() {
		for {
			select {
			case <-browser.ClickedCh:
				if browser.Checked() {
					if err := a.setSysProxyOff(); err != nil {
						log.Error("[SYSTRAY] set sys-proxy off", "err", err)
						continue
					}
					browser.Uncheck()
				} else {
					if err := a.setSysProxyOn(); err != nil {
						log.Error("[SYSTRAY] set sys-proxy on", "err", err)
						continue
					}
					browser.Check()
				}
			case <-global.ClickedCh:
				if global.Checked() {
					if err := a.closeTun2socks(); err != nil {
						log.Error("[SYSTRAY] close tun2socks", "err", err)
						continue
					}
					global.Uncheck()
				} else {
					if !IsRoot() {
						if err := RunMeElevated("-enable-tun2socks"); err != nil {
							log.Error("[SYSTRAY] run me elevated", "err", err)
							continue
						}
						systray.Quit()
						return
					}
					if err := a.createTun2socks(); err != nil {
						log.Error("[SYSTRAY] create tun2socks", "err", err)
						continue
					}
					global.Check()
				}
			case <-a.closing:
				return
			}
		}
	}()

	return browser, global
}

func (a *TrayApp) addCatLogsMenu() {
	catLog := systray.AddMenuItem("查看运行日志", "查看日志")

	go func() {
		for {
			select {
			case <-catLog.ClickedCh:
				if err := catLogFile(a.cfg.Log.FilePath); err != nil {
					log.Error("[SYSTRAY] cat log", "err", err)
				}
			case <-a.closing:
				return
			}
		}
	}()
}

func (a *TrayApp) addExitMenu() {
	quit := systray.AddMenuItem("退出", "退出Easyss APP")

	go func() {
		for {
			select {
			case <-quit.ClickedCh:
				systray.Quit()
			case <-a.closing:
				return
			}
		}
	}()
}

func (a *TrayApp) setSysProxyOn() error {
	return setSysProxy(a.cfg.Local.HTTPPort)
}

func (a *TrayApp) setSysProxyOff() error {
	return unsetSysProxy()
}

func (a *TrayApp) createTun2socks() error {
	if a.tunMgr != nil {
		return nil
	}

	a.cfg.Local.EnableTun2socks = true
	a.tunMgr = tun.New(tun.Config{
		Socks5Addr: fmt.Sprintf("socks5://127.0.0.1:%d", a.cfg.Local.SocksPort),
		LogLevel:   a.cfg.Log.Level,
	})

	if a.cli == nil {
		return fmt.Errorf("client not initialized")
	}
	icmpHandler := tun.NewICMPHandler(a.cli.Router())
	icmpHandler.SetProxy(a.streamHandler, methodFromString(a.cfg.DefaultServer().Method))

	go func() {
		if err := a.tunMgr.Start(icmpHandler); err != nil {
			log.Error("[SYSTRAY] tun2socks start", "err", err)
		}
	}()

	return nil
}

func (a *TrayApp) closeTun2socks() error {
	if a.tunMgr != nil {
		a.tunMgr.Stop()
		a.tunMgr = nil
	}
	a.cfg.Local.EnableTun2socks = false
	return nil
}

func (a *TrayApp) restartService(newCfg *config.ClientConfig) error {
	a.closeService()

	*a.App = App{
		cfg: newCfg,
	}
	return a.Start()
}

func (a *TrayApp) closeService() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.browserMenu != nil && a.browserMenu.Checked() {
		if err := a.setSysProxyOff(); err != nil {
			log.Error("[SYSTRAY] close service: set sysproxy off", "err", err)
		}
	}
	a.Stop()
}

func (a *TrayApp) startLocalService() {
	if a.cfg.Local.SocksPort > 0 && a.cfg.Local.HTTPPort > 0 {
		pacPort := a.cfg.Local.HTTPPort
		_ = pacPort
	}

	if a.browserMenu != nil && a.browserMenu.Checked() {
		if err := a.setSysProxyOn(); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy on", "err", err)
		}
	} else {
		if err := a.setSysProxyOff(); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy off", "err", err)
		}
	}

	if a.cfg.Local.EnableTun2socks {
		if a.tunMenu != nil {
			a.tunMenu.Check()
		}
	}
}

func catLogFile(filePath string) error {
	switch runtime.GOOS {
	case "windows":
		if !util.SysSupportPowershell() {
			return fmt.Errorf("powershell is required on windows")
		}
		winArg := fmt.Sprintf(`-FilePath powershell -ArgumentList "-Command", "Get-Content", "-Wait", "-Tail 100", "%s"`, filePath)
		_, err := util.Command("powershell", "-Command", "Start-Process", winArg)
		return err
	case "linux":
		cmd := []string{"x-terminal-emulator", "-e", "tail", "-50f", filePath}
		if IsRoot() {
			username := ""
			if uid := os.Getenv("PKEXEC_UID"); uid != "" {
				if u, err := user.LookupId(uid); err == nil {
					username = u.Username
				}
			}
			if username == "" {
				if u := os.Getenv("SUDO_USER"); u != "" {
					username = u
				}
			}
			if username != "" {
				newCmd := []string{"runuser", "-u", username, "--"}
				if dbusAddr := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); dbusAddr != "" {
					newCmd = append(newCmd, "env", fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=%s", dbusAddr))
				}
				newCmd = append(newCmd, cmd...)
				cmd = newCmd
				log.Info("[SYSTRAY] cat log: switching to user", "user", username, "cmd", cmd)
			}
		}
		_, err := util.Command(cmd[0], cmd[1:]...)
		return err
	case "darwin":
		_, err := util.Command("open", "-a", "Console", filePath)
		return err
	default:
		return fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}
}

func (a *TrayApp) SetBrowserMenu(m *systray.MenuItem) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.browserMenu = m
}

func (a *TrayApp) BrowserMenu() *systray.MenuItem {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.browserMenu
}

func (a *TrayApp) SetTunMenu(m *systray.MenuItem) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tunMenu = m
}

func (a *TrayApp) TunMenu() *systray.MenuItem {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.tunMenu
}

func methodFromString(s string) protocol.Method {
	return protocol.MethodFromString(s)
}
