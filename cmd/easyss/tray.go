//go:build !headless

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/selfupdate"
)

type TrayApp struct {
	*App

	shell *trayShell
	uwp   uwpMenu

	server *serverMenu
	rule   *radioMenu
	level  *radioMenu
	object *proxyObjectMenu

	autoStartItem *systray.MenuItem

	updater *updater
}

var _ appUI = (*TrayApp)(nil)

// 保留进程存活一段时间，让操作系统显示通知；Windows 气球提示在所属进程退出时消失。
const startupErrorNotifyDelay = 5 * time.Second

func (a *TrayApp) buildTray() {
	root := a.shell.root

	root.AddSubmenu("选择服务器", a.buildSelectServerMenu())
	root.AddSeparator()

	root.AddSubmenu("代理规则", a.buildProxyRuleMenu())
	root.AddSeparator()

	root.AddSubmenu("代理对象", a.buildProxyObjectMenu())
	root.AddSeparator()

	a.uwp.install(root, a.shell.rebuildMenu)

	root.AddSubmenu("日志级别", a.buildLogLevelMenu())
	root.AddSeparator()

	root.Add("查看日志", func() { go a.catLogs() })
	root.AddSeparator()

	a.autoStartItem = root.AddCheckbox("开机启动", IsAutoStartEnabled(), a.toggleAutoStart)
	root.AddSeparator()

	a.updater = newUpdater(updateDeps{
		menu:     root,
		ui:       a.shell,
		port:     func() int { return a.currentConfig().Local.HTTPPort },
		check:    selfupdate.CheckLatest,
		download: selfupdate.Update,
		install:  a.restartAfterUpdate,
		every:    timedUpdateCheckInterval(),
		closing:  a.shell.closing,
	})
	root.Add("退出", a.exitApp)

	a.shell.show()

	// 子菜单已挂上托盘，此时才能开始填充：refreshItems 会往菜单里追加条目，
	// 与 show 里的 SetMenu 并发会同时读写 Menu.Items。
	a.uwp.startRefresh()

	// 必须在 a.Start() 之前装上界面：引擎与通知 goroutine 都在其后派发，读 a.ui 与这里有
	// happens-before。
	a.ui = a

	// 菜单填充完成后再启动服务：带 AppIndicator 的 GNOME 首次查询时能看到非空菜单。
	if err := a.Start(); err != nil {
		log.Error("[EASYSS-V3] tray start", "err", err)
		a.shell.notify(friendlyStartupError(err))
		// 让托盘及其通知短暂存活，用户能读到原因后再退出。刻意不调用 Run()：macOS 每进程只
		// 允许一次 Run()，而系统级通知无需消息循环。
		time.Sleep(startupErrorNotifyDelay)
		os.Exit(1)
	}

	// 非致命启动警告只通知，不阻塞也不退出。
	if warn := a.currentStartupWarn(); warn != nil {
		a.shell.notify(friendlyStartupWarning(warn))
	}

	a.startLocalService()
	go a.server.startStatsLoop(a.currentConfig(), a.shell.closing)
	go a.updater.autoCheckUpdate()
	a.shell.markBuilt()
}

// 用临时托盘呈现配置加载失败（真正的托盘尚未构建）。刻意不调用 Run()：没有 GUI 会话时进程
// 不会挂起，调用方随后仍以失败码退出。
func notifyConfigError(err error) {
	tray := systray.New()
	menu := systray.NewMenu()
	menu.Add("退出", func() { tray.Remove() })
	tray.SetIcon(icon.TrayData).
		SetTooltip(trayAppName).
		SetMenu(menu)

	tray.Show()
	tray.ShowNotification(trayAppName, friendlyConfigError(err))

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
func (a *TrayApp) notify(msg string) { a.shell.notify(msg) }

func (a *TrayApp) serverDomainReady(msg string) {
	a.notify(msg)
}

// 会话已由 session 拆除，这里只碰界面。菜单必须回到未勾选：引擎没在跑，勾着会让用户以为
// 它在跑。
func (a *TrayApp) tunStartFailed(err error) {
	a.object.setTunChecked(false)
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
	a.shell.requestExit()
	a.closeService()

	// 即使 closeService 出错（例如 DNS 恢复期间 osascript 超时），也要清除系统代理。
	_ = a.setSysProxyOff()

	os.Exit(0)
}

func (a *TrayApp) buildSelectServerMenu() *systray.Menu {
	m := systray.NewMenu()
	a.server = newServerMenu(m, a.currentConfig(), a.selectServer)
	return m
}

func (a *TrayApp) selectServer(idx int) {
	go func() {
		if a.server.checked(idx) {
			return
		}
		addr := a.server.addr(idx)
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
		if a.currentCore() != nil && a.server.indexOf(a.currentConfig().DefaultServerAddr()) == idx {
			a.server.setChecked(idx)
			return nil
		}

		a.server.setChecked(-1)

		// 只把切换意图传给 restart，刻意不在停服务之前发布整份配置（见 restartServiceInSequence）。
		clone := a.currentConfig().Clone()
		clone.SetDefaultServerIndex(idx)
		if err := restart(clone); err != nil {
			// restartService 已尽力回滚：还有 core 在运行就按当前配置勾回它；彻底没有服务在运行
			// 时留空——菜单不能声称一个没在工作的服务器已选中。
			if a.currentCore() != nil {
				a.server.setChecked(a.server.indexOf(a.currentConfig().DefaultServerAddr()))
			}
			return err
		}

		a.server.setChecked(idx)
		return nil
	})
}

// 菜单刚被清空，因此切换失败不能只写日志：用户需要知道现在跑的到底是哪个服务器。
func (a *TrayApp) notifyServerSwitchFailure(addr string, err error) {
	msg := fmt.Sprintf("切换到 %s 失败，已回滚到原来的服务器。详情：%v", addr, err)
	if a.currentCore() == nil {
		msg = fmt.Sprintf("切换到 %s 失败，且未能恢复原来的服务器：本机代理已停止，请重试或重启 Easyss。详情：%v", addr, err)
	}
	a.shell.notifyIfReady(msg)
}

func (a *TrayApp) buildProxyRuleMenu() *systray.Menu {
	m := systray.NewMenu()
	rule := a.currentConfig().Routing.ProxyRule
	a.rule = newRadioMenu(m, []radioOption{
		{"auto", "自动(自定义规则+绕过大陆IP域名)", rule == "auto"},
		{"auto_block", "自动+屏蔽广告跟踪", rule == "auto_block"},
		{"reverse_auto", "反向自动(国外访问国内)", rule == "reverse_auto"},
		{"proxy", "代理全部(绕过局域网地址)", rule == "proxy"},
		{"direct", "直接连接", rule == "direct"},
	}, a.setProxyRule)
	return m
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
	a.object = newProxyObjectMenu(m, a.currentConfig(), a.toggleSysProxy, a.toggleTun2socks)
	return m
}

func (a *TrayApp) toggleSysProxy() {
	go toggleCheck(a.object.browser, func(on bool) error {
		if on {
			return a.setSysProxyOn(sysProxyAddr(a.currentConfig()))
		}
		return a.setSysProxyOff()
	}, func(on bool, err error) {
		log.Error("[SYSTRAY] toggle sys-proxy", "on", on, "err", err)
	})
}

func (a *TrayApp) toggleTun2socks() {
	go func() {
		on := a.object.tunChecked()
		log.Info("[SYSTRAY] tun menu clicked", "checked", on)
		if on {
			a.object.setTunChecked(false)
			a.disableTun2socks()
			return
		}
		a.object.setTunChecked(true)
		a.enableTun2socks()
	}()
}

func (a *TrayApp) buildLogLevelMenu() *systray.Menu {
	m := systray.NewMenu()
	level := a.currentConfig().Log.Level
	a.level = newRadioMenu(m, []radioOption{
		{"debug", "debug", level == "debug"},
		{"info", "info", level == "info" || level == ""},
		{"warn", "warn", level == "warn"},
		{"error", "error", level == "error"},
	}, a.setLogLevel)
	return m
}

func (a *TrayApp) setLogLevel(level string) {
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
}

// 失败只写日志会让菜单项看起来像没反应，因此每个失败也以通知呈现。
func (a *TrayApp) catLogs() {
	fallback, err := a.deps.log.openLogFile(a.currentConfig().Log.FilePath)
	switch {
	case err != nil:
		log.Error("[SYSTRAY] cat log", "err", err)
		a.shell.notify(friendlyCatLogError(err))
	case fallback:
		a.shell.notify("未找到终端模拟器，已在默认程序中打开日志快照（最近 500 行）")
	}
}

func (a *TrayApp) toggleAutoStart() {
	go toggleCheck(a.autoStartItem, func(on bool) error {
		if on {
			if err := EnableAutoStart(); err != nil {
				return err
			}
			log.Info("[SYSTRAY] auto-start enabled")
			return nil
		}
		if err := DisableAutoStart(); err != nil {
			return err
		}
		log.Info("[SYSTRAY] auto-start disabled")
		return nil
	}, func(_ bool, err error) {
		log.Error("[SYSTRAY] toggle auto-start", "err", err)
	})
}

func (a *TrayApp) exitApp() {
	go func() {
		// 同步清除系统代理（很快、无需提权）；TUN 清理交给 trayExit()，避免在 osascript 上阻塞
		// 菜单。
		_ = a.setSysProxyOff()
		a.shell.remove()
	}()
}

// 失败必须回滚勾选并通知用户，否则核心仍在提供 SOCKS5/HTTP，而全局流量静默保持直连。
func (a *TrayApp) enableTun2socks() {
	log.Info("[SYSTRAY] enableTun2socks called", "isRoot", IsRoot())

	// 服务端域名未解析时必须拒绝：TUN 会把系统 DNS 指向本机转发服务器，而解析该域名又依赖隧道，
	// 容易形成解析递归；网络未就绪时平台脚本还会因缺默认网关失败。
	if !canStartTunNow(a.currentCore()) {
		log.Warn("[SYSTRAY] tun2socks refused: server domain not resolved yet")
		a.object.setTunChecked(false)
		a.notify("服务端域名尚未解析成功，暂时无法开启系统全局流量；请等待网络恢复后重试")
		return
	}

	if err := a.sess.tunUpAuto(); err != nil {
		log.Error("[SYSTRAY] create tun2socks", "err", err)
		a.object.setTunChecked(false)
		a.notify(friendlyTunError(err))
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

// restartAfterUpdate 在安装完成后重启进程；失败时恢复服务并把错误交给调用方。
// 与菜单切换服务器属同一类临界区：不共用会话序列锁会让两套停/起交错抢本地端口。
func (a *TrayApp) restartAfterUpdate() error {
	var restartErr error
	a.sess.run(func() {
		a.Close()
		// 先释放单例锁，新进程才不会与旧进程竞争单例互斥锁。
		releaseSingletonLock()

		if err := selfupdate.Restart(); err != nil {
			// 新二进制已就位，让旧版本继续运行，由用户手动重启。
			log.Error("[SYSTRAY] restart after update", "err", err)
			// 重新获取单例锁，本进程继续提供服务期间保持唯一实例。
			if lerr := tryAcquireSingletonLock(); lerr != nil {
				log.Error("[SYSTRAY] re-acquire singleton lock after failed restart", "err", lerr)
			}
			// 恢复路径不改变服务器：当前快照当作"意图"传入即可，只读其服务器下标。
			if rerr := a.restartService(a.currentConfig()); rerr != nil {
				log.Error("[SYSTRAY] restore service after failed restart", "err", rerr)
			}
			restartErr = err
			return
		}
		os.Exit(0)
	})
	return restartErr
}

// 托盘只提供菜单状态，切换序列在 App.restartServiceInSequence。
func (a *TrayApp) browserProxyEnabled() bool {
	return a.object.browserChecked()
}

func (a *TrayApp) setTunMenuChecked(checked bool) {
	a.object.setTunChecked(checked)
}

func (a *TrayApp) startLocalService() {
	if a.object.browserChecked() {
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
	a.object.setTunChecked(a.currentConfig().Local.EnableTun2socks)
}
