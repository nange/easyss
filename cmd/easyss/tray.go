//go:build !headless

package main

import (
	"context"
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
	"github.com/nange/easyss/v3/runner"
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
	trayBuilt chan struct{} // buildTray() 完成后关闭

	serverMenuItems []*systray.MenuItem
	serverAddrs     []string
	proxyRuleItems  map[string]*systray.MenuItem
	logLevelItems   map[string]*systray.MenuItem
	autoStartItem   *systray.MenuItem

	// 自更新状态（见 tray_update.go）。
	updateItem    *systray.MenuItem
	updateState   atomic.Int32
	pendingUpdate *selfupdate.Release
	updateMu      sync.Mutex
	// lastNotifiedTag 是已展示过"新版本"系统通知的 tag。
	// 周期性检查会为同一 release 刷新徽标/菜单项，但不得每次都再次弹出通知
	//（见 shouldNotify）。由 updateMu 保护。
	lastNotifiedTag string
	// checkLatest 查询最新发布的 release。它作为字段是为了让测试
	// 可以在无网络访问的情况下运行周期性检查循环；buildTray 将它接入
	// selfupdate.CheckLatest。
	checkLatest func(context.Context, *selfupdate.Client) (*selfupdate.Release, error)
	// updateCheckEvery 是两次周期性更新检查之间的等待时间
	//（updateCheckInterval 加上抖动）。测试会缩短它以观察循环检查行为；
	// 它只在检查循环启动前写入。
	updateCheckEvery time.Duration
	// updateUIMu 串行化更新流程中的托盘 UI 变更（菜单项标签、图标徽标、tooltip）。
	// systray 包在内部保护菜单项，但不保护图标/tooltip 字段，
	// 因此所有由更新驱动的托盘写入都经过这个互斥锁。
	updateUIMu sync.Mutex

	// UWP 回环豁免菜单（仅 Windows）。
	uwpMu    sync.Mutex     //nolint:unused // used in uwp_windows.go
	uwpMenu  *systray.Menu  //nolint:unused // used in uwp_windows.go
	uwpItems []*UWPMenuItem //nolint:unused // used in uwp_windows.go

	// TUN 助手进程管理（darwin 非 root）。
	tunHelperStdin io.WriteCloser // FIFO 写入端；关闭以通知助手进程退出
	tunHelperMu    sync.Mutex
}

// startupErrorNotifyDelay 在启动失败通知后让进程存活一段时间，
// 以便操作系统在客户端退出前显示通知（Windows 气球提示在所属进程退出时消失）。
const startupErrorNotifyDelay = 5 * time.Second

// UWPApp 表示一个已安装的 Windows UWP 应用。
type UWPApp struct {
	Name              string `json:"Name"`
	PackageFamilyName string `json:"PackageFamilyName"`
	Exempt            bool
}

// UWPMenuItem 将 UWP 应用与其托盘菜单项配对。
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
		// macOS 模板图片（单色，随菜单栏主题自适应）。
		a.tray.SetTemplateIcon(icon.TrayData)
	} else {
		// Windows/Linux：SetTemplateIcon 是空操作，使用 SetIcon。
		a.tray.SetIcon(icon.TrayData)
	}
	a.tray.SetTooltip("Easyss")
	a.tray.SetMenu(root)
	a.tray.Show()

	// 引擎启动失败同样需要回滚托盘状态，而启动路径在 App.Start() 内启动引擎，
	// 那里无法访问托盘。因此在调用之前安装，且同一个 TrayApp 比每次
	// App.Start() 更长寿（restartService 只重建内嵌的 App）。
	// notifier 与 hook 一起安装，因为仅靠 hook 会回滚菜单却不说明原因
	//（见 trayStartTunFailure）。
	tunStartFailureHook = a.revertTunStart
	tunStartNotify = a.notifyTunStartFailure
	// 降级启动（开机网络未就绪）后，后台重试解析成功时用同一条系统通知通道
	// 报告一次"网络已恢复、代理可用"。
	serverDomainReadyNotify = a.notifyServerDomainReady
	// TUN 失败的面向用户措辞在这里定义，而不是在 main.go 中，
	// 因为分类需要只有托盘才有的友好文案。直接赋值函数值
	// 使测试可以按名称调用它。
	tunStartErrorText = friendlyTunError

	// 在菜单填充完成后再启动服务，这样桌面环境
	//（尤其是带 AppIndicator 的 GNOME）首次查询时能看到非空菜单。
	if err := a.Start(); err != nil {
		log.Error("[EASYSS-V3] tray start", "err", err)
		a.tray.ShowNotification("Easyss", friendlyStartupError(err))
		// 让托盘（及其通知，例如绑定到图标的 Windows 气球提示）短暂存活，
		// 以便用户能读到原因，然后以失败退出。这里刻意不调用 Run()：
		// macOS 每个进程只允许一次 Run()，而且操作系统级通知 API
		// 无需消息循环即可工作。
		time.Sleep(startupErrorNotifyDelay)
		os.Exit(1)
	}

	// 非致命启动警告（例如服务端域名解析失败且 TUN 被跳过）以通知形式呈现，
	// 不阻塞也不退出：代理核心继续运行。
	if a.startupWarn != nil {
		a.tray.ShowNotification("Easyss", friendlyStartupWarning(a.startupWarn))
	}

	a.startLocalService()
	go a.statsRefresher()
	a.checkLatest = selfupdate.CheckLatest
	a.updateCheckEvery = timedUpdateCheckInterval()
	go a.autoCheckUpdate()
}

// notifyConfigError 使用最小化的临时托盘，通过系统通知呈现配置加载失败
// （例如无效的 JSON），因为真正的托盘尚未构建。它尽力而为：
// systray 公开 API 会吞掉托盘/通知错误，且刻意不调用 Run()，
// 这样在没有 GUI 会话可用时进程绝不会挂起 ——
// 调用方在该函数返回后仍会以失败码退出。
func notifyConfigError(err error) {
	tray := systray.New()
	menu := systray.NewMenu()
	menu.Add("退出", func() { tray.Remove() })
	tray.SetIcon(icon.TrayData).
		SetTooltip("Easyss").
		SetMenu(menu)

	tray.Show()
	tray.ShowNotification("Easyss", friendlyConfigError(err))

	// 让进程再存活一小会儿，确保通知能显示出来
	// （Windows 气泡提示在属主进程退出时会消失）。
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
	// 不随平台/环境变化）。匹配失败则回退到通用提示。
	if strings.Contains(err.Error(), "crypto: password is empty") {
		return "配置错误：服务器密码为空，请在配置文件（或 -k 参数）中设置 password。详情：" + err.Error()
	}
	if strings.Contains(err.Error(), "http proxy requires socks_port to be enabled") {
		return "配置错误：启用 HTTP 代理需要先启用 SOCKS5 代理（socks_port 需大于 0）。详情：" + err.Error()
	}
	return "服务启动失败：" + err.Error()
}

// friendlyStartupWarning 将非致命启动警告转换为用户友好的中文提示。
// 服务端域名解析失败是最常见的一类（开机自启动时网络往往尚未就绪），
// 它不会中止启动：客户端在后台自动重试，网络恢复后代理即可用。
func friendlyStartupWarning(err error) string {
	if errors.Is(err, runner.ErrServerDomainUnresolved) {
		return "启动警告：网络尚未就绪（服务端域名解析失败），客户端已在后台自动重试，" +
			"网络恢复后即可正常代理。详情：" + err.Error()
	}
	return "启动警告：" + err.Error()
}

// notifyTunStartFailure 以系统通知形式呈现 TUN 启动失败。
// 代理核心仍通过 SOCKS5/HTTP 运行 —— 只有系统全局流量受影响，
// 而这正是用户刚请求的状态 —— 所以只写入日志文件的失败
// 看起来会像一次静默的无操作。
//
// 空消息表示没有需要告知用户的内容（见 friendlyTunError）：
// 启动是被有意取消的，而不是失败了。
func (a *TrayApp) notifyTunStartFailure(msg string) {
	if msg == "" {
		return
	}
	a.notifyUser(msg)
}

// notifyServerDomainReady 报告后台重试已解析出服务端域名（网络已恢复）。
// 它安装为 serverDomainReadyNotify，只在降级启动后触发一次。
func (a *TrayApp) notifyServerDomainReady(msg string) {
	if msg == "" {
		return
	}
	a.notifyUser(msg)
}

// friendlyTunError 将 tun2socks 启动失败转换为用户友好的中文提示。
// 返回空字符串表示无需通知（用户主动取消提权，或 TUN 被主动停止）。
func friendlyTunError(err error) string {
	if err == nil || errors.Is(err, context.Canceled) {
		return ""
	}
	// 用户已明确取消提权授权对话：错误文本是 root_linux.go / root_darwin.go
	// 各自的固定字面量（"pkexec/osascript exited before tun helper started"），
	// 属于用户意图而非故障，再弹一次通知只会变成骚扰。
	if strings.Contains(err.Error(), "exited before tun helper started") {
		return ""
	}
	if strings.Contains(err.Error(), "requires root") || errors.Is(err, fs.ErrPermission) {
		return "Tun2socks 启动失败：需要管理员权限，请以 root/管理员身份运行或重试授权。详情：" + err.Error()
	}
	// 设备/路由配置脚本执行失败（例如 Windows 上 netsh 设置地址或 route
	// add 阶梯路由被拒绝）：这类失败会由 Start() 先回滚已写入的路由，所以
	// 文案要说明流量没有被接管，而不是让用户以为只是"没生效"。
	if strings.Contains(err.Error(), "create device") {
		return "Tun2socks 启动失败：TUN 设备/路由配置未完成，已回滚，系统全局流量未被接管；代理（SOCKS5/HTTP）仍可正常使用，可在托盘中重试。详情：" + err.Error()
	}
	return "Tun2socks 启动失败：系统全局流量未生效，代理（SOCKS5/HTTP）仍可正常使用，可在托盘中重试。详情：" + err.Error()
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

	// 即使 closeService 遇到错误（例如 DNS 恢复期间 osascript 超时），
	// 也要确保清除系统代理。
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
				mi.SetChecked(true) // 失败时回滚
			}
		} else {
			mi.SetChecked(true)
			if err := a.setSysProxyOn(); err != nil {
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

// catLogs 从托盘菜单打开日志文件（见 tray_log.go）。失败过去只写入日志文件，
// 这让菜单项看起来像没有反应，因此现在每个失败也会以通知形式呈现。
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
		// 同步清除系统代理 —— 这很快且不需要管理员权限。
		// TUN 清理交给 trayExit() 处理，避免在 osascript 上阻塞菜单。
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
	a.tunMgr = tun.New(a.tunConfig())

	if a.core == nil || a.core.Client == nil {
		return fmt.Errorf("client not initialized")
	}
	icmpHandler := tun.NewICMPHandler(a.core.Client.Router())
	icmpHandler.SetProxy(a.core.StreamHandler, a.methodFromServer())
	a.tunMgr.SetICMPHandler(icmpHandler)

	startTunEngine(a.tunMgr, "device")

	return nil
}

// revertTunStart 撤销一次在 manager 构建后失败的 TUN 启动。
// 它被安装为 tunStartFailureHook，因此菜单开关和启动路径都会走到这里。
//
// 仅取消菜单勾选还不够：closeTun2socks 还会清空 a.tunMgr，
// 否则下次启用会命中 createTun2socks 顶部的"已设置"保护，
// 在菜单声称 TUN 已开启时静默地什么都不做。在 fd 路径上，
// 助手进程已经安装了路由和 DNS，因此也必须告诉它拆除这些。
func (a *TrayApp) revertTunStart() {
	if mi := a.TunMenu(); mi != nil {
		mi.SetChecked(false)
	}
	if err := a.closeTun2socks(); err != nil {
		log.Error("[SYSTRAY] close tun2socks after start failure", "err", err)
	}
}

func (a *TrayApp) closeTun2socks() error {
	a.tunHelperMu.Lock()
	defer a.tunHelperMu.Unlock()

	// 1. 先停止 tun2socks 引擎：它会关闭助手进程传给本进程的 TUN fd。
	//    助手进程的关闭脚本会删除该接口，而 iproute2 无法删除仍附着在
	//    fd 上的设备 —— 会报 "device or resource busy" 并把接口留下来，
	//    连同所有 TUN 路由（它们都绑定在该接口上）。此后流量仍会进入
	//    一个无人读取的设备，表现为 TUN 停止后"网络不可用"。
	if a.tunMgr != nil {
		log.Info("[SYSTRAY] closeTun2socks: stopping tun2socks engine")
		a.tunMgr.Stop()
		a.tunMgr = nil
	}

	// 2. 通过关闭 FIFO 通知助手进程退出。
	//    助手进程检测到 stdin 上的 EOF 后清理路由/DNS 并退出。
	if a.tunHelperStdin != nil {
		log.Info("[SYSTRAY] closeTun2socks: closing helper FIFO")
		a.tunHelperStdin.Close() //nolint:errcheck
		a.tunHelperStdin = nil
	}

	// 3. 助手进程通过文件锁（/tmp/easyss-tun.lock）与任何先前实例协调。
	//    这里无需等待 —— 下一个助手进程会阻塞在锁上，直到本实例退出并释放。
	//    FIFO 文件本身在 tunHelperStdin 关闭时被删除（见 fifoWriter.Close）。

	// 4. 清除 HTTP /tun 配置。
	if a.core != nil && a.core.HTTPServer != nil {
		a.core.HTTPServer.ClearTunConfig()
	}

	a.cfg.Local.EnableTun2socks = false
	return nil
}

// enableTun2socks 在后台 goroutine 中运行 TUN 启用流程，
// 以保持托盘菜单响应。失败时它回滚菜单勾选并通知用户：
// 否则失败不可见，因为代理核心继续提供 SOCKS5/HTTP 服务，
// 而系统全局流量会静默地保持直连。
func (a *TrayApp) enableTun2socks(menu *systray.MenuItem) {
	log.Info("[SYSTRAY] enableTun2socks called", "isRoot", IsRoot())

	// 服务端域名还没解析成功时拒绝启用：TUN 会把系统 DNS 指向本机转发服务器，
	// 而解析服务端域名又依赖隧道本身，容易形成解析递归；网络未就绪时平台脚本
	// 还会因缺默认网关失败。恢复后（就绪通道关闭）再点即正常放行。
	if !canStartTunNow(a.core) {
		log.Warn("[SYSTRAY] tun2socks refused: server domain not resolved yet")
		menu.SetChecked(false)
		a.notifyTunStartFailure("服务端域名尚未解析成功，暂时无法开启系统全局流量；请等待网络恢复后重试")
		return
	}

	if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && !IsRoot() {
		// macOS/Linux 非 root：拉起一个提权助手进程，
		// 打开 TUN 设备、设置路由并把 fd 传回。
		// 助手进程在非 unix 构建上总会失败，但该分支在那里不可达
		//（由 runtime.GOOS 保证）。
		if err := a.createTun2socksViaHelper(); err != nil { //nolint:staticcheck // always fails on non-unix builds; branch unreachable
			log.Error("[SYSTRAY] create tun2socks via helper", "err", err)
			menu.SetChecked(false)
			a.notifyTunStartFailure(friendlyTunError(err))
			return
		}
	} else {
		if err := a.createTun2socks(); err != nil {
			log.Error("[SYSTRAY] create tun2socks", "err", err)
			menu.SetChecked(false)
			a.notifyTunStartFailure(friendlyTunError(err))
			return
		}
	}
}

// disableTun2socks 在后台 goroutine 中运行 TUN 关闭流程，
// 以保持托盘菜单响应。
func (a *TrayApp) disableTun2socks() {
	log.Info("[SYSTRAY] disableTun2socks called")
	if err := a.closeTun2socks(); err != nil {
		log.Error("[SYSTRAY] close tun2socks", "err", err)
	}
}

func (a *TrayApp) restartService(newCfg *config.ClientConfig) error {
	sysProxyEnabled := a.BrowserMenu() != nil && a.BrowserMenu().IsChecked()

	// 停止一切，包括 TUN。在 macOS 上这会提示输入管理员凭据
	// 以清理路由和 DNS —— 在手动切换服务器期间可以接受。
	a.closeService()

	// 防止 a.Start() 重新创建 TUN。切换服务器后 TUN 有意保持关闭；
	// 托盘菜单与实际（关闭）状态保持同步，用户只需一次点击即可重新启用。
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

	// 退出时总是尝试清除系统代理，无论菜单勾选状态如何
	//（由于异步开关或启动顺序，勾选状态可能与实际系统设置不一致）。
	if err := a.setSysProxyOff(); err != nil {
		log.Error("[SYSTRAY] close service: set sysproxy off", "err", err)
	}

	// 在停止核心服务之前停止 TUN 助手进程和引擎。
	// 在非 darwin 或 root 环境下，如果 TUN 不是通过助手进程启动的，
	// closeTun2socks 是空操作。
	if err := a.closeTun2socks(); err != nil {
		log.Error("[SYSTRAY] close service: close tun2socks", "err", err)
	}

	a.Stop()
}

func (a *TrayApp) startLocalService() {
	if a.BrowserMenu() != nil && a.BrowserMenu().IsChecked() {
		if err := a.setSysProxyOn(); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy on", "err", err)
		}
	} else {
		if err := a.setSysProxyOff(); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy off", "err", err)
		}
	}

	// 菜单在 App.Start 之前构建，因此勾选状态可能在启动过程中被改写：TUN 因
	// 服务端域名尚未解析成功而跳过时，App.Start 会把 cfg 置为未启用。这里按
	// cfg 双向同步，菜单始终反映实际是否启用了 TUN（勾选但未运行会让用户
	// 需要点两次才能开启）。
	if a.TunMenu() != nil {
		a.TunMenu().SetChecked(a.cfg.Local.EnableTun2socks)
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
