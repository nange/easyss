//go:build !headless

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/selfupdate"
)

type TrayApp struct {
	*App
	closing     chan struct{}
	mu          sync.RWMutex
	browserMenu *systray.MenuItem
	tunMenu     *systray.MenuItem

	tray      *systray.SystemTray
	rootMenu  *systray.Menu
	trayBuilt chan struct{} // closed after buildTray() completes

	serverMenuItems []*systray.MenuItem
	serverAddrs     []string
	proxyRuleItems  map[string]*systray.MenuItem
	logLevelItems   map[string]*systray.MenuItem
	autoStartItem   *systray.MenuItem

	// Self-update state (see tray_update.go).
	updateItem    *systray.MenuItem
	updateState   atomic.Int32
	pendingUpdate *selfupdate.Release
	updateMu      sync.Mutex
	// updateUIMu serializes the tray UI mutations of the update flow (menu
	// item label, icon badge, tooltip). The systray package protects menu
	// items internally but not the icon/tooltip fields, so all update-driven
	// tray writes go through this mutex.
	updateUIMu sync.Mutex

	// UWP loopback exemption menu (Windows only).
	uwpMu           sync.Mutex        //nolint:unused // used in uwp_windows.go
	uwpMenu         *systray.Menu     //nolint:unused // used in uwp_windows.go
	uwpItems        []*UWPMenuItem    //nolint:unused // used in uwp_windows.go
	uwpOverflowHint *systray.MenuItem //nolint:unused // used in uwp_windows.go

	// TUN helper management (darwin non-root).
	tunHelperStdin io.WriteCloser // FIFO writer; close to signal helper shutdown
	tunHelperMu    sync.Mutex
}

// startupErrorNotifyDelay keeps the process alive after a startup-failure
// notification so the OS can display it before the client exits (Windows
// balloon tips vanish when the owning process exits).
const startupErrorNotifyDelay = 5 * time.Second

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

	a.updateItem = root.Add("检查更新", a.onUpdateClicked)
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
		a.tray.ShowNotification("Easyss", friendlyStartupError(err))
		// Keep the tray (and its notification, e.g. Windows balloon tips
		// bound to the icon) alive briefly so the user can read the reason,
		// then exit with failure. Run() is deliberately not called here:
		// macOS allows only one Run() per process, and the OS-level
		// notification APIs work without the message loop.
		time.Sleep(startupErrorNotifyDelay)
		os.Exit(1)
	}

	// A non-fatal startup warning (e.g. the server domain failed to resolve
	// and TUN was skipped) is surfaced as a notification without blocking
	// or exiting: the proxy core keeps running.
	if a.startupWarn != nil {
		a.tray.ShowNotification("Easyss", friendlyStartupWarning(a.startupWarn))
	}

	a.startLocalService()
	go a.statsRefresher()
	go a.autoCheckUpdate()
}

// notifyConfigError surfaces a config load failure (e.g. invalid JSON)
// via a system notification using a minimal transient tray, because the
// real tray has not been built yet. It is best-effort: the systray public
// API swallows tray/notification errors, and Run() is deliberately not
// called so the process can never hang when no GUI session is available —
// the caller still exits with a failure code after this returns.
func notifyConfigError(err error) {
	tray := systray.New()
	menu := systray.NewMenu()
	menu.Add("退出", func() { tray.Remove() })
	tray.SetIcon(icon.TrayData).
		SetTooltip("Easyss").
		SetMenu(menu)

	tray.Show()
	tray.ShowNotification("Easyss", friendlyConfigError(err))

	// Keep the process alive briefly so the notification is displayed
	// (Windows balloon tips vanish when the owning process exits).
	time.Sleep(startupErrorNotifyDelay)
	tray.Remove()
}

// friendlyConfigError 将配置文件加载错误转换为用户友好的中文提示。
func friendlyConfigError(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "配置文件不存在：" + err.Error()
	default:
		var syntaxErr *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
			return "JSON配置文件解析失败：" + err.Error()
		}
		return "配置文件加载失败：" + err.Error()
	}
}

// friendlyStartupError 将服务启动错误转换为用户友好的中文提示。
func friendlyStartupError(err error) string {
	if isAddrInUse(err) {
		return "服务启动失败：本地端口可能被占用，请关闭占用该端口的程序后重试。详情：" + err.Error()
	}
	// 以下分类按稳定错误文本匹配（均为各自包内固定的字面量错误，
	// 不随平台/环境变化）。匹配失败则落入通用提示。
	if strings.Contains(err.Error(), "crypto: password is empty") {
		return "配置错误：服务器密码为空，请在配置文件（或 -k 参数）中设置 password。详情：" + err.Error()
	}
	if strings.Contains(err.Error(), "http proxy requires socks_port to be enabled") {
		return "配置错误：启用 HTTP 代理需要先启用 SOCKS5 代理（socks_port 需大于 0）。详情：" + err.Error()
	}
	// runner.resolveServerDomain: the server domain failed to resolve, so
	// the proxy cannot reach the server and startup aborts.
	if strings.Contains(err.Error(), "resolution failed") {
		return "服务启动失败：服务端域名解析失败，请检查网络或域名配置。详情：" + err.Error()
	}
	return "服务启动失败：" + err.Error()
}

// friendlyStartupWarning 将非致命启动警告（例如自定义规则文件加载失败）
// 转换为用户友好的中文提示。
func friendlyStartupWarning(err error) string {
	return "启动警告：" + err.Error()
}

// friendlyCatLogError 将「查看日志」失败转换为用户友好的中文提示。
func friendlyCatLogError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errLogFileNotConfigured):
		return "日志文件未配置：请在 config.json 中设置 log.file_path，日志才会写入文件。"
	case errors.Is(err, errNoTerminalEmulator):
		return "未找到可用的终端模拟器：请安装 xdg-terminal-exec、alacritty、foot 等终端，或设置 $TERMINAL 环境变量。"
	case errors.Is(err, fs.ErrNotExist):
		return "日志文件不存在：" + err.Error()
	case errors.Is(err, fs.ErrPermission):
		return "没有权限读取日志文件：" + err.Error()
	default:
		return "打开日志失败：" + err.Error()
	}
}

// isAddrInUse 判断错误是否为"端口已被占用"的绑定失败（Unix 走 errno，
// Windows 走消息匹配，两者兼顾以保证跨平台）。
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) ||
		strings.Contains(err.Error(), "address already in use") ||
		strings.Contains(err.Error(), "Only one usage of each socket address")
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
		a.serverMenuItems = append(a.serverMenuItems, item)
	}

	return m
}

func (a *TrayApp) selectServer(idx int) {
	go func() {
		if a.serverMenuItems[idx].IsChecked() {
			return
		}
		addr := a.serverAddrs[idx]
		log.Info("[SYSTRAY] changing server to", "addr", addr)
		for _, v := range a.serverMenuItems {
			v.SetChecked(false)
		}
		clone := a.cfg.Clone()
		clone.SetDefaultServerIndex(idx)
		if err := a.restartService(clone); err != nil {
			log.Error("[SYSTRAY] changing server to", "addr", addr, "err", err)
			return
		}
		a.serverMenuItems[idx].SetChecked(true)
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
				if mi.IsChecked() {
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
		a.proxyRuleItems[r.rule] = item
	}

	return m
}

func (a *TrayApp) changeProxyRule(rule string) {
	if a.proxyRuleItems[rule].IsChecked() {
		return
	}
	a.setProxyRule(rule)
	for r, item := range a.proxyRuleItems {
		item.SetChecked(r == rule)
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
	a.SetBrowserMenu(browser)

	global := m.AddCheckbox("系统全局流量(Tun2socks)", a.cfg.Local.EnableTun2socks, a.toggleTun2socks)
	a.SetTunMenu(global)

	return m
}

func (a *TrayApp) toggleSysProxy() {
	go func() {
		mi := a.BrowserMenu()
		if mi.IsChecked() {
			mi.SetChecked(false)
			if err := a.setSysProxyOff(); err != nil {
				log.Error("[SYSTRAY] set sys-proxy off", "err", err)
				mi.SetChecked(true) // revert on failure
			}
		} else {
			mi.SetChecked(true)
			if err := a.setSysProxyOn(); err != nil {
				log.Error("[SYSTRAY] set sys-proxy on", "err", err)
				mi.SetChecked(false) // revert on failure
			}
		}
	}()
}

func (a *TrayApp) toggleTun2socks() {
	go func() {
		mi := a.TunMenu()
		log.Info("[SYSTRAY] tun menu clicked", "checked", mi.IsChecked())
		if mi.IsChecked() {
			mi.SetChecked(false)
			a.disableTun2socks()
		} else {
			mi.SetChecked(true)
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
		a.logLevelItems[l.level] = item
	}

	return m
}

func (a *TrayApp) changeLogLevel(level string) {
	if a.logLevelItems[level].IsChecked() {
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
		item.SetChecked(l == level)
	}
}

// catLogs opens the log file from the tray menu (see tray_log.go). Failures
// used to be written to the log file only, which left the menu entry looking
// dead, so every one of them is surfaced as a notification too.
func (a *TrayApp) catLogs() {
	fallback, err := openLogFile(a.cfg.Log.FilePath)
	switch {
	case err != nil:
		log.Error("[SYSTRAY] cat log", "err", err)
		a.tray.ShowNotification("Easyss", friendlyCatLogError(err))
	case fallback:
		a.tray.ShowNotification("Easyss", "未找到终端模拟器，已在默认程序中打开日志快照（最近 500 行）")
	}
}

func (a *TrayApp) toggleAutoStart() {
	go func() {
		if a.autoStartItem.IsChecked() {
			if err := DisableAutoStart(); err != nil {
				log.Error("[SYSTRAY] disable auto-start", "err", err)
				return
			}
			a.autoStartItem.SetChecked(false)
			log.Info("[SYSTRAY] auto-start disabled")
		} else {
			if err := EnableAutoStart(); err != nil {
				log.Error("[SYSTRAY] enable auto-start", "err", err)
				return
			}
			a.autoStartItem.SetChecked(true)
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

	// 1. Stop the tun2socks engine first: it closes the TUN fd that the helper
	//    passed to this process. The helper's close script deletes the
	//    interface, and iproute2 cannot delete a device that is still attached
	//    to a fd — it fails with "device or resource busy" and leaves the
	//    interface behind, together with every TUN route (they are bound to
	//    it). Traffic then keeps entering a device nothing reads from, which
	//    looks like "the network is down" after TUN is stopped.
	if a.tunMgr != nil {
		log.Info("[SYSTRAY] closeTun2socks: stopping tun2socks engine")
		a.tunMgr.Stop()
		a.tunMgr = nil
	}

	// 2. Signal the helper to shut down by closing the FIFO.
	//    The helper detects EOF on stdin, cleans up routes/DNS, and exits.
	if a.tunHelperStdin != nil {
		log.Info("[SYSTRAY] closeTun2socks: closing helper FIFO")
		a.tunHelperStdin.Close() //nolint:errcheck
		a.tunHelperStdin = nil
	}

	// 3. The helper coordinates with any previous instance via a file lock
	//    (/tmp/easyss-tun.lock). No need to wait here — the next helper
	//    will block on the lock until this one exits and releases it.
	//    The FIFO file itself is removed when tunHelperStdin is closed
	//    (see fifoWriter.Close).

	// 4. Clear the HTTP /tun config.
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
		// The helper always fails on non-unix builds, but this branch is
		// unreachable there (guarded by runtime.GOOS).
		if err := a.createTun2socksViaHelper(); err != nil { //nolint:staticcheck // always fails on non-unix builds; branch unreachable
			log.Error("[SYSTRAY] create tun2socks via helper", "err", err)
			menu.SetChecked(false)
			return
		}
	} else {
		if err := a.createTun2socks(); err != nil {
			log.Error("[SYSTRAY] create tun2socks", "err", err)
			menu.SetChecked(false)
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
	sysProxyEnabled := a.BrowserMenu() != nil && a.BrowserMenu().IsChecked()

	// Stop everything including TUN. On macOS this prompts for admin
	// credentials to clean up routes and DNS — acceptable during a
	// manual server switch.
	a.closeService()

	// Prevent a.Start() from recreating TUN. TUN is intentionally left
	// off after a server switch; the tray menu is kept in sync with the
	// actual (off) state so the user can re-enable it with one click.
	newCfg.Local.EnableTun2socks = false
	if tunMenu := a.TunMenu(); tunMenu != nil {
		tunMenu.SetChecked(false)
	}

	*a.App = App{
		cfg: newCfg,
	}
	if err := a.Start(); err != nil {
		return err
	}
	if a.startupWarn != nil {
		log.Warn("[SYSTRAY] restart service: startup warning", "err", a.startupWarn)
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

	if a.BrowserMenu() != nil && a.BrowserMenu().IsChecked() {
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
			a.TunMenu().SetChecked(true)
		}
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
