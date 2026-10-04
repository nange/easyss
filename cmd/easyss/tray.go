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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/selfupdate"
)

type TrayApp struct {
	*App
	closing chan struct{}
	// mu 只保护两个菜单项指针（browserMenu/tunMenu）。它们由 buildTray 在
	// 托盘线程启动之前发布，此后的读者是各菜单回调所在的 goroutine —— 锁在这里
	// 主要是给竞态检测器一个 happens-before 边。它不承担任何服务生命周期职责：
	// 停止/启动序列归 session.run（见 A3 的注释）。
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
}

// 编译期断言：托盘是运行期界面的实现。headless 与 --disable-tray 构建没有
// TrayApp，App.ui 保持 nil（见 appUI）。
var _ appUI = (*TrayApp)(nil)

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
	// 那里无法访问托盘。因此在调用之前把界面装上去（见 appUI），且同一个
	// TrayApp 比每次 App.Start() 更长寿（切换只重启内嵌的会话）。
	// 这个赋值必须早于本函数末尾的 a.Start()：引擎 goroutine 与"网络已恢复"
	// 通知 goroutine 都在那之后才被派发，因此它们读 a.ui 与这里天然有
	// happens-before（headless 与 --disable-tray 构建从不赋值，保持 nil）。
	a.ui = a

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
	if warn := a.currentStartupWarn(); warn != nil {
		a.tray.ShowNotification("Easyss", friendlyStartupWarning(warn))
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

// 以下三个方法是 appUI 的实现（见 main.go）：主程序通过 App.ui 回调它们，
// 因此不需要条件编译，也不需要过去那四个包级函数变量。

// notify 呈现一条面向用户的消息（等价于过去的 tunStartNotify）。它刻意不检查
// "托盘是否已就绪"：初始启动期间（buildTray 尚未返回、trayBuilt 还没关闭）TUN 被
// 跳过的提示必须照常显示，否则"网络尚未就绪"这类开机场景会变得无声无息。
// 通知本身是尽力而为的，没有托盘时 notifyUser 只记日志。
func (a *TrayApp) notify(msg string) {
	if msg == "" {
		return
	}
	a.notifyUser(msg)
}

// serverDomainReady 报告后台重试已解析出服务端域名（网络已恢复）。
// 它只在降级启动后触发一次。
func (a *TrayApp) serverDomainReady(msg string) {
	a.notify(msg)
}

// tunStartFailed 是"TUN 引擎启动失败"在托盘上的唯一处理者：先回滚界面状态
// （菜单勾选，以及提权 helper 已经建立的路由/DNS），再按需说明原因。
//
// 用户主动造成的失败 —— Stop() 取消启动：关闭开关、切换服务器、退出应用 ——
// 由 friendlyTunError 归为"无消息"：那不值得打扰用户。回滚仍然无条件执行：
// 无论谁停止了什么，菜单最终都必须处于未勾选状态。
func (a *TrayApp) tunStartFailed(err error) {
	a.revertTunStart()
	if err == nil {
		return
	}
	a.notifyTunStartFailure(friendlyTunError(err))
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

	// 菜单只读一次配置快照：它构建期间不会有发布（buildTray 在 Start 之前）。
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

// switchServer 执行一次服务器切换：整段"清空勾选 → 停/起 → 勾选结果"在会话
// 序列锁内（连点几下不会并发跑两套停/起），失败时把菜单勾选还原到真正在运行
// 的那个服务器。
//
// restart 由调用方注入（生产代码传 a.restartService），使测试无需真的重启服务、
// 也不会改写运行测试的机器的系统代理与端口。注意它是序列体：注入的实现自身不得
// 再取序列锁。
func (a *TrayApp) switchServer(idx int, restart func(*config.ClientConfig) error) error {
	return a.sess.runErr(func() error {
		// 排队期间状态可能已经变成"这个服务器正在运行"（上一次点击已经切到它了）：
		// 此时只需要把勾选确认回来，不必再停一次、起一次。
		if a.currentCore() != nil && a.runningServerIndex() == idx {
			a.setCheckedServer(idx)
			return nil
		}

		a.setCheckedServer(-1)

		// 目标配置只作为"切换意图"传给 restart（生产实现只看它的服务器下标，见
		// restartServiceInSequence）：这里刻意不在停服务之前把整份配置发布出去。
		clone := a.currentConfig().Clone()
		clone.SetDefaultServerIndex(idx)
		if err := restart(clone); err != nil {
			// restartService 已经尽力回滚到切换前的服务器：回滚成功（还有 core
			// 在运行）就按当前配置勾回它；彻底没有服务在运行时留空——菜单不能
			// 声称一个没在工作的服务器已选中，那正是"切换失败 + 本机断网"的样子。
			if a.currentCore() != nil {
				a.setCheckedServer(a.runningServerIndex())
			}
			return err
		}

		a.setCheckedServer(idx)
		return nil
	})
}

// runningServerIndex 返回当前配置指向的服务器在菜单里的下标（找不到返回 -1）。
// 配置是切换/回滚的唯一事实来源：菜单勾选必须跟着它走。
func (a *TrayApp) runningServerIndex() int {
	addr := a.currentConfig().DefaultServerAddr()
	for i, candidate := range a.serverAddrs {
		if candidate == addr {
			return i
		}
	}
	return -1
}

// setCheckedServer 只勾选下标 idx 的服务器；idx < 0 表示全部取消勾选。
func (a *TrayApp) setCheckedServer(idx int) {
	for i, item := range a.serverMenuItems {
		item.SetChecked(i == idx)
	}
}

// notifyServerSwitchFailure 告知用户切换失败。切换失败不能只写日志：菜单刚刚被
// 清空过，用户需要知道现在到底跑的是哪个服务器（或者什么都没跑）。
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

	url := fmt.Sprintf("http://127.0.0.1:%d/stats", a.currentConfig().Local.HTTPPort)
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
	// 运行中的会话立即生效（路由引擎），持久化的偏好走 copy-on-write 快照。
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

// catLogs 从托盘菜单打开日志文件（见 tray_log.go）。失败过去只写入日志文件，
// 这让菜单项看起来像没有反应，因此现在每个失败也会以通知形式呈现。
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
		// 同步清除系统代理 —— 这很快且不需要管理员权限。
		// TUN 清理交给 trayExit() 处理，避免在 osascript 上阻塞菜单。
		_ = a.setSysProxyOff()
		a.tray.Remove()
	}()
}

// setSysProxyOn/setSysProxyOff 走 sysProxyApply/sysProxyRevert 这两个包级钩子
// （而不是直接调用实现），使测试可以观察托盘路径上的系统代理改动，
// 而不必触碰运行测试的机器的真实代理配置。
func (a *TrayApp) setSysProxyOn() error {
	return sysProxyApply(a.currentConfig().Local.HTTPPort)
}

func (a *TrayApp) setSysProxyOff() error {
	return sysProxyRevert()
}

// revertTunStart 撤销一次在 manager 构建后失败的 TUN 启动。它是
// appUI.tunStartFailed 的第一步，因此菜单开关和启动路径都会走到这里。
//
// 仅取消菜单勾选还不够：session.tunDown 还会清空 tunMgr，否则下次启用会命中
// session.tunUp 顶部的"已设置"保护，在菜单声称 TUN 已开启时静默地什么都不做。
// 在 fd 路径上，助手进程已经安装了路由和 DNS，因此也必须告诉它拆除这些。
func (a *TrayApp) revertTunStart() {
	if mi := a.TunMenu(); mi != nil {
		mi.SetChecked(false)
	}
	if err := a.sess.tunDown(); err != nil {
		log.Error("[SYSTRAY] close tun2socks after start failure", "err", err)
	}
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
	if !canStartTunNow(a.currentCore()) {
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
		if err := a.sess.tunUpViaHelper(); err != nil { //nolint:staticcheck // always fails on non-unix builds; branch unreachable
			log.Error("[SYSTRAY] create tun2socks via helper", "err", err)
			menu.SetChecked(false)
			a.notifyTunStartFailure(friendlyTunError(err))
			return
		}
	} else {
		if err := a.sess.tunUp(); err != nil {
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
	if err := a.sess.tunDown(); err != nil {
		log.Error("[SYSTRAY] close tun2socks", "err", err)
	}
}

// startService 是切换/重启的默认 start 步骤：用当前配置快照启动一个新会话。
// 参数被刻意忽略（生产语义）：配置由 restartServiceInSequence 以增量方式发布到
// 当前快照上，App.Start 读到的就是它。
func (a *TrayApp) startService(*config.ClientConfig) error { return a.Start() }

// restartService 执行一次完整的"停→起"切换，出错时回滚到切换前的服务器。
// 它是 switchServer 的默认 restart 步骤，因此是序列体：只能在 session.run 内调用
// （见 restartServiceInSequence）。
func (a *TrayApp) restartService(newCfg *config.ClientConfig) error {
	return a.restartServiceInSequence(newCfg, a.startService)
}

// restartServiceWith 是序列体 restartServiceInSequence 的序列化入口：整段"停→起"
// 持有 session 的序列锁。它供不持有序列的调用方使用（测试，以及将来需要单独重启
// 一次会话的路径）。
//
// 序列锁不可重入：已经位于 session.run 闭包内的调用方必须直接调用
// restartServiceInSequence，否则会死锁。
func (a *TrayApp) restartServiceWith(newCfg *config.ClientConfig, start func(*config.ClientConfig) error) error {
	return a.sess.runErr(func() error {
		return a.restartServiceInSequence(newCfg, start)
	})
}

// restartServiceInSequence 是切换的序列体；start 由调用方注入，使测试可以驱动
// "新服务起不来 → 回滚到旧服务器"这条路径，而不必真的启动代理核心。
//
// newCfg 只是"切换意图"的载体：本函数只从它取目标服务器下标，然后把这**一条
// 增量**应用到当前快照上（见下面的 updateConfig），其余字段一律以当前快照为准。
// 原因是 stopServiceInSequence 可能要数秒（macOS 上要等 TUN 拆除的管理员凭据），
// 而序列锁只串行化两套"停/起"，串不住不持锁的菜单路径——若在这里发布一份停服务
// 之前取的全量快照，用户在这期间改的代理规则/日志级别就会被静默还原。
//
// start 收到的配置是"调用时刻生效的快照"，只读（生产实现忽略它，测试据此判断
// 目标服务器与注入失败）。
func (a *TrayApp) restartServiceInSequence(newCfg *config.ClientConfig, start func(*config.ClientConfig) error) error {
	targetIdx := newCfg.DefaultServerIndex()

	snap := a.currentConfig()
	prevIdx, prevTun := snap.DefaultServerIndex(), snap.Local.EnableTun2socks

	sysProxyEnabled := a.BrowserMenu() != nil && a.BrowserMenu().IsChecked()

	// 停止一切，包括 TUN。在 macOS 上这会提示输入管理员凭据
	// 以清理路由和 DNS —— 在手动切换服务器期间可以接受。
	a.stopServiceInSequence()

	// 停完之后才发布切换意图，且只改这次切换真正要改的两个字段：目标服务器，
	// 以及"切换后 TUN 保持关闭"（托盘菜单与实际状态同步，用户一次点击即可
	// 重新启用）。CAS 发布因此会把停服务期间的菜单改动合并进来，而不是覆盖它。
	a.updateConfig(func(c *config.ClientConfig) {
		c.SetDefaultServerIndex(targetIdx)
		c.Local.EnableTun2socks = false
	})
	if tunMenu := a.TunMenu(); tunMenu != nil {
		tunMenu.SetChecked(false)
	}

	restoreSysProxy := func() {
		if !sysProxyEnabled {
			return
		}
		if err := a.setSysProxyOn(); err != nil {
			log.Error("[SYSTRAY] restart service: restore sysproxy on", "err", err)
		}
	}

	if err := start(a.currentConfig()); err != nil {
		// 回滚同样只回退这次切换改掉的两个字段（服务器选择与 TUN 偏好），
		// 保留菜单在这期间的最新改动。回滚也失败时两个错误一起上报
		//（调用方据此判断"完全没有服务在运行"）。
		a.updateConfig(func(c *config.ClientConfig) {
			c.SetDefaultServerIndex(prevIdx)
			c.Local.EnableTun2socks = prevTun
		})
		if tunMenu := a.TunMenu(); tunMenu != nil {
			tunMenu.SetChecked(prevTun)
		}
		prevAddr := a.currentConfig().DefaultServerAddr()
		if rollbackErr := start(a.currentConfig()); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback to %s: %w", prevAddr, rollbackErr))
		}
		log.Warn("[SYSTRAY] restart service: rolled back to the previous server",
			"addr", prevAddr, "err", err)
		restoreSysProxy()
		return err
	}

	// startupWarn 由 start 里的那次 App.Start（或 buildTray 的初始 Start）写入；
	// 这里的恢复流程与那次 Start 分属不同 goroutine，因此必须走访问器（它读的是
	// 会话自己的锁，见 session.startupWarn）。
	if warn := a.currentStartupWarn(); warn != nil {
		log.Warn("[SYSTRAY] restart service: startup warning", "err", warn)
	}

	restoreSysProxy()
	return nil
}

// closeService 停止当前会话：撤销系统代理 → 拆 TUN → 停核心。整段在会话序列锁内
// （见 session.run），因此退出路径与切换/自更新重启不会交错——这个性质过去是
// closeService 整段持有 TrayApp.mu 顺带得到的（那把锁只负责两个菜单项指针，却把
// 菜单读挡住了最长可达几十秒的 TUN 拆除），现在由显式的序列锁提供。
func (a *TrayApp) closeService() {
	a.sess.run(a.stopServiceInSequence)
}

// stopServiceInSequence 是关闭会话的序列体，只能在 session.run 内调用。
func (a *TrayApp) stopServiceInSequence() {
	// 退出时总是尝试清除系统代理，无论菜单勾选状态如何
	//（由于异步开关或启动顺序，勾选状态可能与实际系统设置不一致）。
	if err := a.setSysProxyOff(); err != nil {
		log.Error("[SYSTRAY] close service: set sysproxy off", "err", err)
	}

	// 在停止核心服务之前停止 TUN 助手进程和引擎。
	// 在非 darwin 或 root 环境下，如果 TUN 不是通过助手进程启动的，
	// session.tunDown 是空操作。
	if err := a.sess.tunDown(); err != nil {
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
