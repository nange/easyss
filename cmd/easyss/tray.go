//go:build !without_tray

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/systray"
)

type TrayApp struct {
	*App
	closing     chan struct{}
	mu          sync.RWMutex
	browserMenu *systray.MenuItem
	tunMenu     *systray.MenuItem

	tray     *systray.SystemTray
	rootMenu *systray.Menu
	checked  map[*systray.MenuItem]bool

	serverMenuItems []*systray.MenuItem
	serverAddrs     []string
	proxyRuleItems  map[string]*systray.MenuItem
	logLevelItems   map[string]*systray.MenuItem
	autoStartItem   *systray.MenuItem

	// UWP loopback exemption menu (Windows only).
	uwpMu    sync.Mutex
	uwpMenu  *systray.Menu
	uwpItems []*UWPMenuItem

	// TUN helper management (darwin non-root).
	tunHelperStdin io.WriteCloser // FIFO writer; close to signal helper shutdown
	tunHelperMu    sync.Mutex
}

// UWPApp represents an installed Windows UWP application.
type UWPApp struct {
	Name              string `json:"Name"`
	PackageFamilyName string `json:"PackageFamilyName"`
	Exempt            bool
}

// UWPMenuItem pairs a UWP app with its tray menu item.
type UWPMenuItem struct {
	MenuItem *systray.MenuItem
	App      *UWPApp
	Mu       sync.RWMutex
}

// setChecked updates both the native checkbox state and the local state map.
// gogpu/systray has no Checked() query, so the map is the source of truth.
func (a *TrayApp) setChecked(mi *systray.MenuItem, v bool) {
	if mi == nil {
		return
	}
	a.mu.Lock()
	if a.checked == nil {
		a.checked = make(map[*systray.MenuItem]bool)
	}
	a.checked[mi] = v
	a.mu.Unlock()
	mi.SetChecked(v)
}

func (a *TrayApp) isChecked(mi *systray.MenuItem) bool {
	if mi == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.checked[mi]
}

func (a *TrayApp) buildTray() {
	root := systray.NewMenu()
	a.rootMenu = root

	root.AddSubmenu("选择服务器", a.buildSelectServerMenu())
	root.AddSeparator()

	root.AddSubmenu("代理规则", a.buildProxyRuleMenu())
	root.AddSeparator()

	root.AddSubmenu("代理对象", a.buildProxyObjectMenu())
	root.AddSeparator()

	a.addUWPLoopbackMenu(root)

	root.AddSubmenu("日志级别", a.buildLogLevelMenu())
	root.AddSeparator()

	root.Add("查看日志", func() { go a.catLogs() })
	root.AddSeparator()

	a.autoStartItem = root.AddCheckbox("开机启动", IsAutoStartEnabled(), a.toggleAutoStart)
	root.AddSeparator()

	root.Add("退出", a.exitApp)

	a.tray = systray.New()
	if runtime.GOOS == "darwin" {
		// macOS template image (monochrome, adapts to menu bar theme).
		a.tray.SetTemplateIcon(icon.TrayData)
	} else {
		// Windows/Linux: SetTemplateIcon is a no-op, use SetIcon.
		a.tray.SetIcon(icon.TrayData)
	}
	a.tray.SetTooltip("Easyss")
	a.tray.SetMenu(root)
	a.tray.Show()

	// Start service after menu is populated so that desktop environments
	// (especially GNOME with AppIndicator) see a non-empty menu on first query.
	if err := a.Start(); err != nil {
		log.Error("[EASYSS-V3] tray start", "err", err)
		os.Exit(1)
	}

	a.startLocalService()
	go a.statsRefresher()
}

func (a *TrayApp) trayExit() {
	select {
	case a.closing <- struct{}{}:
	default:
	}
	a.closeService()

	// Ensure system proxy is cleared even if closeService encountered
	// an error (e.g. osascript timeout during DNS restore).
	_ = a.setSysProxyOff()

	os.Exit(0)
}

func (a *TrayApp) buildSelectServerMenu() *systray.Menu {
	m := systray.NewMenu()

	addrs := a.cfg.ServerListAddrs()
	if len(addrs) == 0 {
		addrs = []string{a.cfg.DefaultServerAddr()}
	}
	a.serverAddrs = addrs
	a.serverMenuItems = make([]*systray.MenuItem, 0, len(addrs))

	for idx, addr := range addrs {
		checked := addr == a.cfg.DefaultServerAddr()
		item := m.AddCheckbox(addr, checked, func(idx int) func() {
			return func() { a.selectServer(idx) }
		}(idx))
		a.setChecked(item, checked)
		a.serverMenuItems = append(a.serverMenuItems, item)
	}

	return m
}

func (a *TrayApp) selectServer(idx int) {
	go func() {
		if a.isChecked(a.serverMenuItems[idx]) {
			return
		}
		addr := a.serverAddrs[idx]
		log.Info("[SYSTRAY] changing server to", "addr", addr)
		for _, v := range a.serverMenuItems {
			a.setChecked(v, false)
		}
		clone := a.cfg.Clone()
		clone.SetDefaultServerIndex(idx)
		if err := a.restartService(clone); err != nil {
			log.Error("[SYSTRAY] changing server to", "addr", addr, "err", err)
			return
		}
		a.setChecked(a.serverMenuItems[idx], true)
		log.Info("[SYSTRAY] changes server success to", "addr", addr)
	}()
}

func (a *TrayApp) statsRefresher() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	url := fmt.Sprintf("http://127.0.0.1:%d/stats", a.cfg.Local.HTTPPort)
	httpClient := &http.Client{Timeout: 2 * time.Second}

	for {
		select {
		case <-ticker.C:
			rttMs, downSpeed := fetchStats(httpClient, url)
			for i, mi := range a.serverMenuItems {
				if a.isChecked(mi) {
					mi.SetLabel(formatTitle(a.serverAddrs[i], rttMs, downSpeed))
					break
				}
			}
		case <-a.closing:
			return
		}
	}
}

func fetchStats(client *http.Client, url string) (rttMs float64, downSpeed string) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()

	var snap struct {
		AvgRTTMs           float64 `json:"avg_rtt_ms"`
		DownloadSpeedHuman string  `json:"download_speed_human"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return 0, ""
	}
	return snap.AvgRTTMs, snap.DownloadSpeedHuman
}

func formatTitle(addr string, rttMs float64, downSpeed string) string {
	var extra string
	if rttMs > 0 {
		extra = fmt.Sprintf("%dms", int64(rttMs))
	}
	if downSpeed != "" {
		if extra != "" {
			extra += "  "
		}
		extra += "↓" + downSpeed
	}
	if extra != "" {
		return addr + "\t" + extra
	}
	return addr
}

func (a *TrayApp) buildProxyRuleMenu() *systray.Menu {
	m := systray.NewMenu()
	a.proxyRuleItems = make(map[string]*systray.MenuItem)

	rules := []struct {
		rule    string
		label   string
		checked bool
	}{
		{"auto", "自动(自定义规则+绕过大陆IP域名)", a.cfg.Routing.ProxyRule == "auto"},
		{"auto_block", "自动+屏蔽广告跟踪", a.cfg.Routing.ProxyRule == "auto_block"},
		{"reverse_auto", "反向自动(国外访问国内)", a.cfg.Routing.ProxyRule == "reverse_auto"},
		{"proxy", "代理全部(绕过局域网地址)", a.cfg.Routing.ProxyRule == "proxy"},
		{"direct", "直接连接", a.cfg.Routing.ProxyRule == "direct"},
	}

	for _, r := range rules {
		item := m.AddCheckbox(r.label, r.checked, func(rule string) func() {
			return func() { go a.changeProxyRule(rule) }
		}(r.rule))
		a.setChecked(item, r.checked)
		a.proxyRuleItems[r.rule] = item
	}

	return m
}

func (a *TrayApp) changeProxyRule(rule string) {
	if a.isChecked(a.proxyRuleItems[rule]) {
		return
	}
	a.setProxyRule(rule)
	for r, item := range a.proxyRuleItems {
		a.setChecked(item, r == rule)
	}
}

func (a *TrayApp) setProxyRule(rule string) {
	if a.core != nil && a.core.Client != nil {
		a.core.Client.SetProxyRule(rule)
	}
	a.cfg.Routing.ProxyRule = rule
	log.Info("[SYSTRAY] proxy rule changed", "rule", rule)
}

func (a *TrayApp) buildProxyObjectMenu() *systray.Menu {
	m := systray.NewMenu()

	browserChecked := !a.cfg.Local.DisableSysProxy
	browser := m.AddCheckbox("浏览器(设置系统代理)", browserChecked, a.toggleSysProxy)
	a.setChecked(browser, browserChecked)
	a.SetBrowserMenu(browser)

	global := m.AddCheckbox("系统全局流量(Tun2socks)", a.cfg.Local.EnableTun2socks, a.toggleTun2socks)
	a.setChecked(global, a.cfg.Local.EnableTun2socks)
	a.SetTunMenu(global)

	return m
}

func (a *TrayApp) toggleSysProxy() {
	go func() {
		mi := a.BrowserMenu()
		if a.isChecked(mi) {
			a.setChecked(mi, false)
			if err := a.setSysProxyOff(); err != nil {
				log.Error("[SYSTRAY] set sys-proxy off", "err", err)
				a.setChecked(mi, true) // revert on failure
			}
		} else {
			a.setChecked(mi, true)
			if err := a.setSysProxyOn(); err != nil {
				log.Error("[SYSTRAY] set sys-proxy on", "err", err)
				a.setChecked(mi, false) // revert on failure
			}
		}
	}()
}

func (a *TrayApp) toggleTun2socks() {
	go func() {
		mi := a.TunMenu()
		log.Info("[SYSTRAY] tun menu clicked", "checked", a.isChecked(mi))
		if a.isChecked(mi) {
			a.setChecked(mi, false)
			a.disableTun2socks()
		} else {
			a.setChecked(mi, true)
			a.enableTun2socks(mi)
		}
	}()
}

func (a *TrayApp) buildLogLevelMenu() *systray.Menu {
	m := systray.NewMenu()
	a.logLevelItems = make(map[string]*systray.MenuItem)

	levels := []struct {
		level   string
		checked bool
	}{
		{"debug", a.cfg.Log.Level == "debug"},
		{"info", a.cfg.Log.Level == "info" || a.cfg.Log.Level == ""},
		{"warn", a.cfg.Log.Level == "warn"},
		{"error", a.cfg.Log.Level == "error"},
	}

	for _, l := range levels {
		item := m.AddCheckbox(l.level, l.checked, func(level string) func() {
			return func() { go a.changeLogLevel(level) }
		}(l.level))
		a.setChecked(item, l.checked)
		a.logLevelItems[l.level] = item
	}

	return m
}

func (a *TrayApp) changeLogLevel(level string) {
	if a.isChecked(a.logLevelItems[level]) {
		return
	}
	a.cfg.Log.Level = level
	log.Info("[SYSTRAY] log level changed", "level", level)

	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	log.SetLevel(slogLevel)

	for l, item := range a.logLevelItems {
		a.setChecked(item, l == level)
	}
}

func (a *TrayApp) catLogs() {
	if err := a.catLog(); err != nil {
		log.Error("[SYSTRAY] cat log", "err", err)
	}
}

func (a *TrayApp) catLog() error {
	filePath := a.cfg.Log.FilePath
	if filePath == "" {
		return fmt.Errorf("log file path is empty, please configure log.file_path in config.json")
	}
	return catLogFile(filePath)
}

func (a *TrayApp) toggleAutoStart() {
	go func() {
		if a.isChecked(a.autoStartItem) {
			if err := DisableAutoStart(); err != nil {
				log.Error("[SYSTRAY] disable auto-start", "err", err)
				return
			}
			a.setChecked(a.autoStartItem, false)
			log.Info("[SYSTRAY] auto-start disabled")
		} else {
			if err := EnableAutoStart(); err != nil {
				log.Error("[SYSTRAY] enable auto-start", "err", err)
				return
			}
			a.setChecked(a.autoStartItem, true)
			log.Info("[SYSTRAY] auto-start enabled")
		}
	}()
}

func (a *TrayApp) exitApp() {
	go func() {
		// Clear the system proxy synchronously — this is fast
		// and does not require admin. Leave TUN cleanup for
		// trayExit() to avoid blocking the menu on osascript.
		_ = a.setSysProxyOff()
		a.tray.Remove()
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
		DNSServer:  tunDNS(a.cfg),
	})

	if a.core == nil || a.core.Client == nil {
		return fmt.Errorf("client not initialized")
	}
	icmpHandler := tun.NewICMPHandler(a.core.Client.Router())
	icmpHandler.SetProxy(a.core.StreamHandler, methodFromString(a.cfg.DefaultServer().Method))
	a.tunMgr.SetICMPHandler(icmpHandler)

	go func() {
		if err := a.tunMgr.Start(); err != nil {
			log.Error("[SYSTRAY] tun2socks start", "err", err)
		}
	}()

	return nil
}

func (a *TrayApp) closeTun2socks() error {
	a.tunHelperMu.Lock()
	defer a.tunHelperMu.Unlock()

	log.Info("[SYSTRAY] closeTun2socks called",
		"stdinNil", a.tunHelperStdin == nil,
		"tunMgrNil", a.tunMgr == nil)

	// 1. Signal the helper to shut down by closing the FIFO.
	//    The helper detects EOF on stdin, cleans up routes/DNS, and exits.
	if a.tunHelperStdin != nil {
		a.tunHelperStdin.Close() //nolint:errcheck
		a.tunHelperStdin = nil
	}
	log.Info("[SYSTRAY] closeTun2socks: fifo closed, stopping engine")

	// 2. Stop the tun2socks engine (no route/DNS cleanup — helper handles it).
	if a.tunMgr != nil {
		log.Info("[SYSTRAY] closeTun2socks: calling tunMgr.Stop")
		a.tunMgr.Stop()
		log.Info("[SYSTRAY] closeTun2socks: tunMgr.Stop done")
		a.tunMgr = nil
	}

	// 3. The helper coordinates with any previous instance via a file lock
	//    (/tmp/easyss-tun.lock). No need to wait here — the next helper
	//    will block on the lock until this one exits and releases it.

	// 4. Clean up the FIFO and clear the HTTP /tun config.
	fifoPath := fmt.Sprintf("/tmp/easyss-tun-ctrl-%d.fifo", os.Getpid())
	os.Remove(fifoPath) //nolint:errcheck

	if a.core != nil && a.core.HTTPServer != nil {
		a.core.HTTPServer.ClearTunConfig()
	}

	a.cfg.Local.EnableTun2socks = false
	return nil
}

// enableTun2socks runs the TUN enable flow in a background goroutine so the
// tray menu remains responsive. On failure it reverts the menu checkmark.
func (a *TrayApp) enableTun2socks(menu *systray.MenuItem) {
	log.Info("[SYSTRAY] enableTun2socks called", "isRoot", IsRoot())
	if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && !IsRoot() {
		// Non-root on macOS/Linux: spawn an elevated helper process to
		// open the TUN device, set up routes, and pass the fd back.
		if err := a.createTun2socksViaHelper(); err != nil {
			log.Error("[SYSTRAY] create tun2socks via helper", "err", err)
			a.setChecked(menu, false)
			return
		}
	} else {
		if err := a.createTun2socks(); err != nil {
			log.Error("[SYSTRAY] create tun2socks", "err", err)
			a.setChecked(menu, false)
			return
		}
	}
}

// disableTun2socks runs the TUN disable flow in a background goroutine so
// the tray menu remains responsive.
func (a *TrayApp) disableTun2socks() {
	log.Info("[SYSTRAY] disableTun2socks called")
	if err := a.closeTun2socks(); err != nil {
		log.Error("[SYSTRAY] close tun2socks", "err", err)
	}
}

func (a *TrayApp) restartService(newCfg *config.ClientConfig) error {
	sysProxyEnabled := a.BrowserMenu() != nil && a.isChecked(a.BrowserMenu())

	// Stop everything including TUN. On macOS this prompts for admin
	// credentials to clean up routes and DNS — acceptable during a
	// manual server switch.
	a.closeService()

	// Prevent a.Start() from recreating TUN. TUN is intentionally left
	// off after a server switch; the tray menu is kept in sync with the
	// actual (off) state so the user can re-enable it with one click.
	newCfg.Local.EnableTun2socks = false
	if tunMenu := a.TunMenu(); tunMenu != nil {
		a.setChecked(tunMenu, false)
	}

	*a.App = App{
		cfg: newCfg,
	}
	if err := a.Start(); err != nil {
		return err
	}

	if sysProxyEnabled {
		if err := a.setSysProxyOn(); err != nil {
			log.Error("[SYSTRAY] restart service: restore sysproxy on", "err", err)
		}
	}
	return nil
}

func (a *TrayApp) closeService() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Always try to clear the system proxy on exit, regardless of the
	// menu checkmark state (which may be inconsistent with the actual
	// system setting due to async toggle or startup ordering).
	if err := a.setSysProxyOff(); err != nil {
		log.Error("[SYSTRAY] close service: set sysproxy off", "err", err)
	}

	// Stop TUN helper and engine before stopping the core services.
	// On non-darwin or root, closeTun2socks is a no-op if TUN was not
	// started via helper.
	if err := a.closeTun2socks(); err != nil {
		log.Error("[SYSTRAY] close service: close tun2socks", "err", err)
	}

	a.Stop()
}

func (a *TrayApp) startLocalService() {
	if a.cfg.Local.SocksPort > 0 && a.cfg.Local.HTTPPort > 0 {
		pacPort := a.cfg.Local.HTTPPort
		_ = pacPort
	}

	if a.BrowserMenu() != nil && a.isChecked(a.BrowserMenu()) {
		if err := a.setSysProxyOn(); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy on", "err", err)
		}
	} else {
		if err := a.setSysProxyOff(); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy off", "err", err)
		}
	}

	if a.cfg.Local.EnableTun2socks {
		if a.TunMenu() != nil {
			a.setChecked(a.TunMenu(), true)
		}
	}
}

func catLogFile(filePath string) error {
	var linuxCmd []string

	switch runtime.GOOS {
	case "linux":
		title := "View Easyss Logs"
		switch {
		case util.SysSupportXTerminalEmulator():
			linuxCmd = []string{"x-terminal-emulator", "-e", "tail", "-50f", filePath}
		case util.SysSupportGnomeTerminal():
			linuxCmd = []string{"gnome-terminal", "--hide-menubar", "--title", title, "--", "tail", "-50f", filePath}
		case util.SysSupportMateTerminal():
			linuxCmd = []string{"mate-terminal", "--hide-menubar", "--title", title, "--", "tail", "-50f", filePath}
		case util.SysSupportKonsole():
			linuxCmd = []string{"konsole", "--hide-menubar", "-e", "tail", "-50f", filePath}
		case util.SysSupportXfce4Terminal():
			linuxCmd = []string{"xfce4-terminal", "--hide-menubar", "--hide-toolbar", "--title", title, "--command", fmt.Sprintf("tail -50f %s", filePath)}
		case util.SysSupportLxterminal():
			linuxCmd = []string{"lxterminal", "--title", title, "--command", fmt.Sprintf("tail -50f %s", filePath)}
		case util.SysSupportTerminator():
			linuxCmd = []string{"terminator", "--title", title, "--command", fmt.Sprintf("tail -50f %s", filePath)}
		}

		if len(linuxCmd) > 0 && IsRoot() {
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
				newCmd = append(newCmd, linuxCmd...)
				linuxCmd = newCmd
				log.Info("[SYSTRAY] cat log: switching to user", "user", username, "cmd", linuxCmd)
			}
		}
		if len(linuxCmd) == 0 {
			return fmt.Errorf("no supported terminal emulator found")
		}
		_, err := util.Command(linuxCmd[0], linuxCmd[1:]...)
		return err
	case "windows":
		_, err := util.Command("cmd", "/c", "start", "powershell", "-NoExit", "-Command",
			fmt.Sprintf("Get-Content -Wait -Tail 100 '%s'", filePath))
		return err
	case "darwin":
		_, err := util.Command("osascript", "-e", fmt.Sprintf(`tell application "Terminal" to do script "tail -f \"%s\""`, filePath), "-e", `tell application "Terminal" to activate`)
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
