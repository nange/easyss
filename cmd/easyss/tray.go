//go:build !headless

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/util"
)

type TrayApp struct {
	*App
	closing chan struct{}
	// 只保护两个菜单项指针；停/起序列归 session.run，与本锁无关。
	mu          sync.RWMutex
	browserMenu *systray.MenuItem
	tunMenu     *systray.MenuItem

	tray      *systray.SystemTray
	rootMenu  *systray.Menu
	trayBuilt chan struct{}

	serverMenuItems []*systray.MenuItem
	serverAddrs     []string
	proxyRuleItems  map[string]*systray.MenuItem
	logLevelItems   map[string]*systray.MenuItem
	autoStartItem   *systray.MenuItem

	updateItem    *systray.MenuItem
	updateState   atomic.Int32
	pendingUpdate *selfupdate.Release
	updateMu      sync.Mutex
	// 已展示过"新版本"通知的 tag：周期性检查只为同一 release 刷新徽标，不得重复弹通知。
	lastNotifiedTag string
	checkLatest     func(context.Context, *selfupdate.Client) (*selfupdate.Release, error)
	// 含抖动，只在循环启动前写入。
	updateCheckEvery time.Duration
	// systray 保护菜单项，但不保护图标/tooltip 字段，更新流程里的 UI 变更必须经它串行化。
	updateUIMu sync.Mutex

	// UWP 回环豁免菜单（仅 Windows）。
	uwpMu    sync.Mutex     //nolint:unused // used in uwp_windows.go
	uwpMenu  *systray.Menu  //nolint:unused // used in uwp_windows.go
	uwpItems []*UWPMenuItem //nolint:unused // used in uwp_windows.go
}

var _ appUI = (*TrayApp)(nil)

// 保留进程存活一段时间，让操作系统显示通知；Windows 气球提示在所属进程退出时消失。
const startupErrorNotifyDelay = 5 * time.Second

type UWPApp struct {
	Name              string `json:"Name"`
	PackageFamilyName string `json:"PackageFamilyName"`
	Exempt            bool
}

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
		// 模板图标只在 macOS 生效（单色，随菜单栏主题自适应），Windows/Linux 用 SetIcon。
		a.tray.SetTemplateIcon(icon.TrayData)
	} else {
		a.tray.SetIcon(icon.TrayData)
	}
	a.tray.SetTooltip("Easyss")
	a.tray.SetMenu(root)
	a.tray.Show()

	// 必须在 a.Start() 之前装上界面：引擎与通知 goroutine 都在其后派发，读 a.ui 与这里有
	// happens-before。
	a.ui = a

	// 菜单填充完成后再启动服务：带 AppIndicator 的 GNOME 首次查询时能看到非空菜单。
	if err := a.Start(); err != nil {
		log.Error("[EASYSS-V3] tray start", "err", err)
		a.tray.ShowNotification("Easyss", friendlyStartupError(err))
		// 让托盘及其通知短暂存活，用户能读到原因后再退出。刻意不调用 Run()：macOS 每进程只
		// 允许一次 Run()，而系统级通知无需消息循环。
		time.Sleep(startupErrorNotifyDelay)
		os.Exit(1)
	}

	// 非致命启动警告只通知，不阻塞也不退出。
	if warn := a.currentStartupWarn(); warn != nil {
		a.tray.ShowNotification("Easyss", friendlyStartupWarning(warn))
	}

	a.startLocalService()
	go a.statsRefresher()
	a.checkLatest = selfupdate.CheckLatest
	a.updateCheckEvery = timedUpdateCheckInterval()
	go a.autoCheckUpdate()
}

// 用临时托盘呈现配置加载失败（真正的托盘尚未构建）。刻意不调用 Run()：没有 GUI 会话时进程
// 不会挂起，调用方随后仍以失败码退出。
func notifyConfigError(err error) {
	tray := systray.New()
	menu := systray.NewMenu()
	menu.Add("退出", func() { tray.Remove() })
	tray.SetIcon(icon.TrayData).
		SetTooltip("Easyss").
		SetMenu(menu)

	tray.Show()
	tray.ShowNotification("Easyss", friendlyConfigError(err))

	// Windows 气泡提示在属主进程退出时会消失，因此要等通知显示出来。
	time.Sleep(startupErrorNotifyDelay)
	tray.Remove()
}

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

func friendlyStartupError(err error) string {
	if isAddrInUse(err) {
		return "服务启动失败：本地端口可能被占用，请关闭占用该端口的程序后重试。详情：" + err.Error()
	}
	if errors.Is(err, crypto.ErrPasswordEmpty) {
		return "配置错误：服务器密码为空，请在配置文件（或 -k 参数）中设置 password。详情：" + err.Error()
	}
	if errors.Is(err, runner.ErrSocksRequired) {
		return "配置错误：启用 HTTP 代理需要先启用 SOCKS5 代理（socks_port 需大于 0）。详情：" + err.Error()
	}
	return "服务启动失败：" + err.Error()
}

// 服务端域名解析失败是最常见的一类（开机自启动时网络往往尚未就绪），它不中止启动。
func friendlyStartupWarning(err error) string {
	if errors.Is(err, runner.ErrServerDomainUnresolved) {
		return "启动警告：网络尚未就绪（服务端域名解析失败），客户端已在后台自动重试，" +
			"网络恢复后即可正常代理。详情：" + err.Error()
	}
	return "启动警告：" + err.Error()
}

// 初始启动期间托盘尚未就绪也必须照常显示，否则"网络尚未就绪"这类开机场景会无声无息。
func (a *TrayApp) notify(msg string) {
	if msg == "" {
		return
	}
	a.notifyUser(msg)
}

func (a *TrayApp) serverDomainReady(msg string) {
	a.notify(msg)
}

// 会话已由 session 拆除，这里只碰界面。菜单必须回到未勾选：引擎没在跑，勾着会让用户以为
// 它在跑。
func (a *TrayApp) tunStartFailed(err error) {
	if mi := a.TunMenu(); mi != nil {
		mi.SetChecked(false)
	}
	if err == nil {
		return
	}
	a.notify(friendlyTunError(err))
}

// 返回空字符串表示无需通知（用户主动取消提权，或 TUN 被主动停止）。
func friendlyTunError(err error) string {
	if err == nil || errors.Is(err, context.Canceled) {
		return ""
	}
	// 用户已明确取消提权授权，属于用户意图而非故障，再弹通知只会变成骚扰。
	if errors.Is(err, errTunHelperStartup) {
		return ""
	}
	if errors.Is(err, fs.ErrPermission) {
		return "Tun2socks 启动失败：需要管理员权限，请以 root/管理员身份运行或重试授权。详情：" + err.Error()
	}
	// 这类失败会由 Start() 先回滚已写入的路由，文案要说明流量没有被接管。
	if errors.Is(err, tun.ErrCreateDevice) {
		return "Tun2socks 启动失败：TUN 设备/路由配置未完成，已回滚，系统全局流量未被接管；代理（SOCKS5/HTTP）仍可正常使用，可在托盘中重试。详情：" + err.Error()
	}
	return "Tun2socks 启动失败：系统全局流量未生效，代理（SOCKS5/HTTP）仍可正常使用，可在托盘中重试。详情：" + err.Error()
}

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

func (a *TrayApp) trayExit() {
	select {
	case a.closing <- struct{}{}:
	default:
	}
	a.closeService()

	// 即使 closeService 出错（例如 DNS 恢复期间 osascript 超时），也要清除系统代理。
	_ = a.setSysProxyOff()

	os.Exit(0)
}

func (a *TrayApp) buildSelectServerMenu() *systray.Menu {
	m := systray.NewMenu()

	cfg := a.currentConfig()
	addrs := cfg.ServerListAddrs()
	if len(addrs) == 0 {
		addrs = []string{cfg.DefaultServerAddr()}
	}
	a.serverAddrs = addrs
	a.serverMenuItems = make([]*systray.MenuItem, 0, len(addrs))

	for idx, addr := range addrs {
		checked := addr == cfg.DefaultServerAddr()
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
		if err := a.switchServer(idx, a.restartService); err != nil {
			log.Error("[SYSTRAY] changing server to", "addr", addr, "err", err)
			a.notifyServerSwitchFailure(addr, err)
			return
		}
		log.Info("[SYSTRAY] changes server success to", "addr", addr)
	}()
}

// 整段"清空勾选 → 停/起 → 勾选结果"在会话序列锁内，连点几下不会并发跑两套停/起；restart
// 是序列体，注入的实现自身不得再取序列锁。
func (a *TrayApp) switchServer(idx int, restart func(*config.ClientConfig) error) error {
	return a.sess.runErr(func() error {
		// 排队期间可能已经切到目标服务器：把勾选确认回来即可，不必再停一次、起一次。
		if a.currentCore() != nil && a.runningServerIndex() == idx {
			a.setCheckedServer(idx)
			return nil
		}

		a.setCheckedServer(-1)

		// 只把切换意图传给 restart，刻意不在停服务之前发布整份配置（见 restartServiceInSequence）。
		clone := a.currentConfig().Clone()
		clone.SetDefaultServerIndex(idx)
		if err := restart(clone); err != nil {
			// restartService 已尽力回滚：还有 core 在运行就按当前配置勾回它；彻底没有服务在运行
			// 时留空——菜单不能声称一个没在工作的服务器已选中。
			if a.currentCore() != nil {
				a.setCheckedServer(a.runningServerIndex())
			}
			return err
		}

		a.setCheckedServer(idx)
		return nil
	})
}

func (a *TrayApp) runningServerIndex() int {
	addr := a.currentConfig().DefaultServerAddr()
	for i, candidate := range a.serverAddrs {
		if candidate == addr {
			return i
		}
	}
	return -1
}

func (a *TrayApp) setCheckedServer(idx int) {
	for i, item := range a.serverMenuItems {
		item.SetChecked(i == idx)
	}
}

// 菜单刚被清空，因此切换失败不能只写日志：用户需要知道现在跑的到底是哪个服务器。
func (a *TrayApp) notifyServerSwitchFailure(addr string, err error) {
	msg := fmt.Sprintf("切换到 %s 失败，已回滚到原来的服务器。详情：%v", addr, err)
	if a.currentCore() == nil {
		msg = fmt.Sprintf("切换到 %s 失败，且未能恢复原来的服务器：本机代理已停止，请重试或重启 Easyss。详情：%v", addr, err)
	}
	if !a.trayReady() {
		log.Warn("[SYSTRAY] notify skipped: tray not ready", "msg", msg)
		return
	}
	a.notifyUser(msg)
}

func (a *TrayApp) statsRefresher() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	cfg := a.currentConfig()
	url := fmt.Sprintf("http://%s/stats", util.LocalProxyDialAddr(cfg.Local.BindAll, cfg.Local.HTTPPort))
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

func (a *TrayApp) buildProxyRuleMenu() *systray.Menu {
	m := systray.NewMenu()
	a.proxyRuleItems = make(map[string]*systray.MenuItem)

	proxyRule := a.currentConfig().Routing.ProxyRule
	rules := []struct {
		rule    string
		label   string
		checked bool
	}{
		{"auto", "自动(自定义规则+绕过大陆IP域名)", proxyRule == "auto"},
		{"auto_block", "自动+屏蔽广告跟踪", proxyRule == "auto_block"},
		{"reverse_auto", "反向自动(国外访问国内)", proxyRule == "reverse_auto"},
		{"proxy", "代理全部(绕过局域网地址)", proxyRule == "proxy"},
		{"direct", "直接连接", proxyRule == "direct"},
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
	// 运行中的会话立即生效，持久化的偏好走 copy-on-write 快照。
	if core := a.currentCore(); core != nil && core.Client != nil {
		core.Client.SetProxyRule(rule)
	}
	a.updateConfig(func(c *config.ClientConfig) { c.Routing.ProxyRule = rule })
	log.Info("[SYSTRAY] proxy rule changed", "rule", rule)
}

func (a *TrayApp) buildProxyObjectMenu() *systray.Menu {
	m := systray.NewMenu()

	cfg := a.currentConfig()
	browserChecked := !cfg.Local.DisableSysProxy
	browser := m.AddCheckbox("浏览器(设置系统代理)", browserChecked, a.toggleSysProxy)
	a.SetBrowserMenu(browser)

	global := m.AddCheckbox("系统全局流量(Tun2socks)", cfg.Local.EnableTun2socks, a.toggleTun2socks)
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
				mi.SetChecked(true) // 失败时回滚
			}
		} else {
			mi.SetChecked(true)
			if err := a.setSysProxyOn(sysProxyAddr(a.currentConfig())); err != nil {
				log.Error("[SYSTRAY] set sys-proxy on", "err", err)
				mi.SetChecked(false) // 失败时回滚
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

	logLevel := a.currentConfig().Log.Level
	levels := []struct {
		level   string
		checked bool
	}{
		{"debug", logLevel == "debug"},
		{"info", logLevel == "info" || logLevel == ""},
		{"warn", logLevel == "warn"},
		{"error", logLevel == "error"},
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
	a.updateConfig(func(c *config.ClientConfig) { c.Log.Level = level })
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

// 失败只写日志会让菜单项看起来像没反应，因此每个失败也以通知呈现。
func (a *TrayApp) catLogs() {
	fallback, err := openLogFile(a.currentConfig().Log.FilePath)
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
		// 同步清除系统代理（很快、无需提权）；TUN 清理交给 trayExit()，避免在 osascript 上阻塞
		// 菜单。
		_ = a.setSysProxyOff()
		a.tray.Remove()
	}()
}

// 失败必须回滚勾选并通知用户，否则核心仍在提供 SOCKS5/HTTP，而全局流量静默保持直连。
func (a *TrayApp) enableTun2socks(menu *systray.MenuItem) {
	log.Info("[SYSTRAY] enableTun2socks called", "isRoot", IsRoot())

	// 服务端域名未解析时必须拒绝：TUN 会把系统 DNS 指向本机转发服务器，而解析该域名又依赖隧道，
	// 容易形成解析递归；网络未就绪时平台脚本还会因缺默认网关失败。
	if !canStartTunNow(a.currentCore()) {
		log.Warn("[SYSTRAY] tun2socks refused: server domain not resolved yet")
		menu.SetChecked(false)
		a.notify("服务端域名尚未解析成功，暂时无法开启系统全局流量；请等待网络恢复后重试")
		return
	}

	if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && !IsRoot() {
		// 非 root 时拉起提权助手打开设备、配置路由并把 fd 传回；助手在非 unix 构建上总会失败，
		// 但该分支由 runtime.GOOS 保证不可达。
		if err := a.sess.tunUpViaHelper(); err != nil { //nolint:staticcheck // always fails on non-unix builds; branch unreachable
			log.Error("[SYSTRAY] create tun2socks via helper", "err", err)
			menu.SetChecked(false)
			a.notify(friendlyTunError(err))
			return
		}
	} else {
		if err := a.sess.tunUp(); err != nil {
			log.Error("[SYSTRAY] create tun2socks", "err", err)
			menu.SetChecked(false)
			a.notify(friendlyTunError(err))
			return
		}
	}
}

func (a *TrayApp) disableTun2socks() {
	log.Info("[SYSTRAY] disableTun2socks called")
	// teardown 中发现的问题由 tunDown 自己记日志/通知界面，不中止退出流程。
	a.sess.tunDown()
}

// 参数被刻意忽略：配置由 restartServiceInSequence 以增量方式发布到当前快照上，App.Start 读到的
// 就是它。
func (a *TrayApp) startService(*config.ClientConfig) error { return a.Start() }

// 只能在 session.run 内调用（见 restartServiceInSequence）。
func (a *TrayApp) restartService(newCfg *config.ClientConfig) error {
	return a.restartServiceInSequence(newCfg, a.startService)
}

// 整段停/起持有 session 序列锁，供不持有序列的调用方使用。序列锁不可重入：已在 session.run
// 闭包内的调用方必须直接调用 restartServiceInSequence，否则死锁。
func (a *TrayApp) restartServiceWith(newCfg *config.ClientConfig, start func(*config.ClientConfig) error) error {
	return a.sess.runErr(func() error {
		return a.restartServiceInSequence(newCfg, start)
	})
}

// 整段在会话序列锁内，退出路径与切换/自更新重启不会交错。
func (a *TrayApp) closeService() {
	a.sess.run(a.Close)
}

// 托盘只提供菜单状态，切换序列在 App.restartServiceInSequence。
func (a *TrayApp) browserProxyEnabled() bool {
	return a.BrowserMenu() != nil && a.BrowserMenu().IsChecked()
}

func (a *TrayApp) setTunMenuChecked(checked bool) {
	if mi := a.TunMenu(); mi != nil {
		mi.SetChecked(checked)
	}
}

func (a *TrayApp) startLocalService() {
	if a.BrowserMenu() != nil && a.BrowserMenu().IsChecked() {
		if err := a.setSysProxyOn(sysProxyAddr(a.currentConfig())); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy on", "err", err)
		}
	} else {
		if err := a.setSysProxyOff(); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy off", "err", err)
		}
	}

	// 菜单在 App.Start 之前构建，勾选状态可能被启动过程改写；这里按 cfg 双向同步，避免
	// "勾选但未运行"让用户需要点两次才能开启。
	if a.TunMenu() != nil {
		a.TunMenu().SetChecked(a.currentConfig().Local.EnableTun2socks)
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
