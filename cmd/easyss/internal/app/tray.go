//go:build !headless

package app

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
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/cmd/easyss/icon"
	"github.com/nange/easyss/v3/cmd/easyss/internal/autostart"
	"github.com/nange/easyss/v3/cmd/easyss/internal/logview"
	"github.com/nange/easyss/v3/cmd/easyss/internal/singleton"
	"github.com/nange/easyss/v3/cmd/easyss/internal/sysproxy"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tray"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tunhelper"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/selfupdate"
)

type trayApp struct {
	*App

	shell *tray.Shell
	uwp   tray.UWP

	server *tray.ServerMenu
	object *tray.ObjectMenu

	autoStartItem *systray.MenuItem

	updater *tray.Updater
}

var _ appUI = (*trayApp)(nil)

// 保留进程存活一段时间，让操作系统显示通知；Windows 气球提示在所属进程退出时消失。
const startupErrorNotifyDelay = 5 * time.Second

func (a *trayApp) buildTray() {
	root := a.shell.Root()

	root.AddSubmenu("选择服务器", a.buildSelectServerMenu())
	root.AddSeparator()

	root.AddSubmenu("代理规则", a.buildProxyRuleMenu())
	root.AddSeparator()

	root.AddSubmenu("代理对象", a.buildProxyObjectMenu())
	root.AddSeparator()

	a.uwp.Install(root, a.shell.RebuildMenu)

	root.AddSubmenu("日志级别", a.buildLogLevelMenu())
	root.AddSeparator()

	root.Add("查看日志", func() { go a.catLogs() })
	root.AddSeparator()

	a.autoStartItem = root.AddCheckbox("开机启动", autostart.IsAutoStartEnabled(), a.toggleAutoStart)
	root.AddSeparator()

	a.updater = tray.NewUpdater(tray.UpdateDeps{
		Menu:     root,
		UI:       a.shell,
		Port:     func() int { return a.currentConfig().Local.HTTPPort },
		Check:    selfupdate.CheckLatest,
		Download: selfupdate.Update,
		Install:  a.restartAfterUpdate,
		Every:    tray.UpdateCheckInterval(),
		Closing:  a.shell.Closing(),
	})
	root.Add("退出", a.exitApp)

	a.shell.Show()

	// 子菜单已挂上托盘，此时才能开始填充：refreshItems 会往菜单里追加条目，
	// 与 show 里的 SetMenu 并发会同时读写 Menu.Items。
	a.uwp.StartRefresh()

	// 必须在 a.Start() 之前装上界面：引擎与通知 goroutine 都在其后派发，读 a.ui 与这里有
	// happens-before。
	a.ui = a

	// 菜单填充完成后再启动服务：带 AppIndicator 的 GNOME 首次查询时能看到非空菜单。
	if err := a.Start(); err != nil {
		log.Error("[EASYSS-V3] tray start", "err", err)
		a.shell.Notify(friendlyStartupError(err))
		// 让托盘及其通知短暂存活，用户能读到原因后再退出。刻意不调用 Run()：macOS 每进程只
		// 允许一次 Run()，而系统级通知无需消息循环。
		time.Sleep(startupErrorNotifyDelay)
		os.Exit(1)
	}

	// 非致命启动警告只通知，不阻塞也不退出。
	if warn := a.currentStartupWarn(); warn != nil {
		a.shell.Notify(friendlyStartupWarning(warn))
	}

	a.startLocalService()
	go a.server.StartStatsLoop(a.currentConfig(), a.shell.Closing())
	go a.updater.AutoCheckUpdate()
	a.shell.MarkBuilt()
}

// 用临时托盘呈现配置加载失败（真正的托盘尚未构建）。刻意不调用 Run()：没有 GUI 会话时进程
// 不会挂起，调用方随后仍以失败码退出。
func NotifyConfigError(err error) {
	st := systray.New()
	menu := systray.NewMenu()
	menu.Add("退出", func() { st.Remove() })
	st.SetIcon(icon.TrayData).
		SetTooltip(tray.AppName).
		SetMenu(menu)

	st.Show()
	st.ShowNotification(tray.AppName, friendlyConfigError(err))

	// Windows 气泡提示在属主进程退出时会消失，因此要等通知显示出来。
	time.Sleep(startupErrorNotifyDelay)
	st.Remove()
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
	if errors.Is(err, runner.ErrForwardDNSRequiresSocks) {
		return "配置错误：enable_forward_dns 需要本地 SOCKS5 入口（socks_port 需大于 0）：" +
			"转发器的查询要回到本机 SOCKS5 才能按域名分流；运行中还需保持 TUN 开启，否则转发器会拒答。详情：" + err.Error()
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
func (a *trayApp) notify(msg string) { a.shell.Notify(msg) }

func (a *trayApp) serverDomainReady(msg string) {
	a.notify(msg)
}

// 会话已由 session 拆除，这里只碰界面。菜单必须回到未勾选：引擎没在跑，勾着会让用户以为
// 它在跑。
func (a *trayApp) tunStartFailed(err error) {
	a.object.SetTunChecked(false)
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
	if errors.Is(err, tunhelper.ErrStartup) {
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

func (a *trayApp) trayExit() {
	a.shell.RequestExit()
	a.closeService()

	// 即使 closeService 出错（例如 DNS 恢复期间 osascript 超时），也要清除系统代理。
	_ = a.setSysProxyOff()

	os.Exit(0)
}

func (a *trayApp) buildSelectServerMenu() *systray.Menu {
	m := systray.NewMenu()
	a.server = tray.NewServerMenu(m, a.currentConfig(), a.selectServer)
	return m
}

func (a *trayApp) selectServer(idx int) {
	go func() {
		if a.server.Checked(idx) {
			return
		}
		addr := a.server.Addr(idx)
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
func (a *trayApp) switchServer(idx int, restart func(*clientconfig.ClientConfig) error) error {
	return a.sess.runErr(func() error {
		// 排队期间可能已经切到目标服务器：把勾选确认回来即可，不必再停一次、起一次。
		if a.currentCore() != nil && a.server.IndexOf(a.currentConfig().DefaultServerAddr()) == idx {
			a.server.SetChecked(idx)
			return nil
		}

		a.server.SetChecked(-1)

		// 只把切换意图传给 restart，刻意不在停服务之前发布整份配置（见 restartServiceInSequence）。
		clone := a.currentConfig().Clone()
		clone.SetDefaultServerIndex(idx)
		if err := restart(clone); err != nil {
			// restartService 已尽力回滚：还有 core 在运行就按当前配置勾回它；彻底没有服务在运行
			// 时留空——菜单不能声称一个没在工作的服务器已选中。
			if a.currentCore() != nil {
				a.server.SetChecked(a.server.IndexOf(a.currentConfig().DefaultServerAddr()))
			}
			return err
		}

		a.server.SetChecked(idx)
		return nil
	})
}

// 菜单刚被清空，因此切换失败不能只写日志：用户需要知道现在跑的到底是哪个服务器。
func (a *trayApp) notifyServerSwitchFailure(addr string, err error) {
	msg := fmt.Sprintf("切换到 %s 失败，已回滚到原来的服务器。详情：%v", addr, err)
	if a.currentCore() == nil {
		msg = fmt.Sprintf("切换到 %s 失败，且未能恢复原来的服务器：本机代理已停止，请重试或重启 Easyss。详情：%v", addr, err)
	}
	a.shell.NotifyIfReady(msg)
}

func (a *trayApp) buildProxyRuleMenu() *systray.Menu {
	m := systray.NewMenu()
	rule := a.currentConfig().Routing.ProxyRule
	tray.NewRadioMenu(m, []tray.RadioOption{
		{Key: "auto", Label: "自动(自定义规则+绕过大陆IP域名)", Checked: rule == "auto"},
		{Key: "auto_block", Label: "自动+屏蔽广告跟踪", Checked: rule == "auto_block"},
		{Key: "reverse_auto", Label: "反向自动(国外访问国内)", Checked: rule == "reverse_auto"},
		{Key: "proxy", Label: "代理全部(绕过局域网地址)", Checked: rule == "proxy"},
		{Key: "direct", Label: "直接连接", Checked: rule == "direct"},
	}, a.setProxyRule)
	return m
}

func (a *trayApp) setProxyRule(rule string) {
	// 运行中的会话立即生效，持久化的偏好走 copy-on-write 快照。
	if core := a.currentCore(); core != nil && core.Client != nil {
		core.Client.SetProxyRule(rule)
	}
	a.updateConfig(func(c *clientconfig.ClientConfig) { c.Routing.ProxyRule = rule })
	log.Info("[SYSTRAY] proxy rule changed", "rule", rule)
}

func (a *trayApp) buildProxyObjectMenu() *systray.Menu {
	m := systray.NewMenu()
	a.object = tray.NewObjectMenu(m, a.currentConfig(), a.toggleSysProxy, a.toggleTun2socks)
	return m
}

func (a *trayApp) toggleSysProxy() {
	go tray.ToggleCheck(a.object.BrowserItem(), func(on bool) error {
		if on {
			return a.setSysProxyOn(sysproxy.Addr(a.currentConfig()))
		}
		return a.setSysProxyOff()
	}, func(on bool, err error) {
		log.Error("[SYSTRAY] toggle sys-proxy", "on", on, "err", err)
	})
}

func (a *trayApp) toggleTun2socks() {
	go func() {
		on := a.object.TunChecked()
		log.Info("[SYSTRAY] tun menu clicked", "checked", on)
		if on {
			a.object.SetTunChecked(false)
			a.disableTun2socks()
			return
		}
		a.object.SetTunChecked(true)
		a.enableTun2socks()
	}()
}

func (a *trayApp) buildLogLevelMenu() *systray.Menu {
	m := systray.NewMenu()
	level := a.currentConfig().Log.Level
	tray.NewRadioMenu(m, []tray.RadioOption{
		{Key: "debug", Label: "debug", Checked: level == "debug"},
		{Key: "info", Label: "info", Checked: level == "info" || level == ""},
		{Key: "warn", Label: "warn", Checked: level == "warn"},
		{Key: "error", Label: "error", Checked: level == "error"},
	}, a.setLogLevel)
	return m
}

func (a *trayApp) setLogLevel(level string) {
	a.updateConfig(func(c *clientconfig.ClientConfig) { c.Log.Level = level })
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
func (a *trayApp) catLogs() {
	fallback, err := a.deps.log.Open(a.currentConfig().Log.FilePath)
	switch {
	case err != nil:
		log.Error("[SYSTRAY] cat log", "err", err)
		a.shell.Notify(logview.FriendlyError(err))
	case fallback:
		a.shell.Notify("未找到终端模拟器，已在默认程序中打开日志快照（最近 500 行）")
	}
}

func (a *trayApp) toggleAutoStart() {
	go tray.ToggleCheck(a.autoStartItem, func(on bool) error {
		if on {
			if err := autostart.EnableAutoStart(); err != nil {
				return err
			}
			log.Info("[SYSTRAY] auto-start enabled")
			return nil
		}
		if err := autostart.DisableAutoStart(); err != nil {
			return err
		}
		log.Info("[SYSTRAY] auto-start disabled")
		return nil
	}, func(on bool, err error) {
		log.Error("[SYSTRAY] toggle auto-start", "on", on, "err", err)
		a.shell.NotifyIfReady("设置开机启动失败：" + err.Error())
	})
}

func (a *trayApp) exitApp() {
	go func() {
		// 同步清除系统代理（很快、无需提权）；TUN 清理交给 trayExit()，避免在 osascript 上阻塞
		// 菜单。
		_ = a.setSysProxyOff()
		a.shell.Remove()
	}()
}

// 失败必须回滚勾选并通知用户，否则核心仍在提供 SOCKS5/HTTP，而全局流量静默保持直连。
func (a *trayApp) enableTun2socks() {
	log.Info("[SYSTRAY] enableTun2socks called", "elevated", a.deps.isElevated())

	// 服务端域名未解析时必须拒绝：TUN 会把系统 DNS 指向本机转发服务器，而解析该域名又依赖隧道，
	// 容易形成解析递归；网络未就绪时平台脚本还会因缺默认网关失败。
	// 必须在提权之前判断：否则用户先过一遍 UAC、整个进程重启，新实例随后在启动路径里
	// 跳过 TUN 并把偏好清回 false，等于"授权了却没开"。
	if !canStartTunNow(a.currentCore()) {
		log.Warn("[SYSTRAY] tun2socks refused: server domain not resolved yet")
		a.object.SetTunChecked(false)
		a.notify("服务端域名尚未解析成功，暂时无法开启系统全局流量；请等待网络恢复后重试")
		return
	}

	// 非提权进程建不了 TUN：请求提权，由接管本次点击的管理员实例去装（Windows 重启自身）。
	if !a.deps.isElevated() && a.requestTunElevation() {
		return
	}

	if err := a.sess.tunUpAuto(); err != nil {
		log.Error("[SYSTRAY] create tun2socks", "err", err)
		a.object.SetTunChecked(false)
		a.notify(friendlyTunError(err))
	}
}

func (a *trayApp) disableTun2socks() {
	log.Info("[SYSTRAY] disableTun2socks called")
	// teardown 中发现的问题由 tunDown 自己记日志/通知界面，不中止退出流程。
	a.sess.tunDown()
}

// requestTunElevation 把"开启 TUN"交给一个管理员权限的实例，返回 true 表示这次点击已被
// 接管：调用方不得再在原地建 TUN。darwin/linux 返回 false，由 tunUpAuto 走 pkexec/osascript。
func (a *trayApp) requestTunElevation() bool {
	err := a.deps.requestElevation(a.App)
	if errors.Is(err, errElevationUnsupported) {
		return false
	}

	// 本进程不再负责 TUN：勾选留给接管的新实例按 -enable-tun2socks 重新建立。
	a.object.SetTunChecked(false)
	switch {
	case errors.Is(err, errElevationCancelled):
		log.Warn("[SYSTRAY] elevation cancelled by the user")
		a.notify("已取消管理员授权，系统全局流量未开启")
	case err != nil:
		log.Error("[SYSTRAY] request elevation for tun2socks", "err", err)
		a.notify("请求管理员权限失败，系统全局流量未开启。详情：" + err.Error())
	default:
		// 新实例已经在等单实例锁：本进程按正常退出流程撤系统代理、拆 TUN、停核心后退出，
		// 锁随进程退出释放（见 exitApp）。
		log.Info("[SYSTRAY] restarting as administrator for tun2socks")
		a.exitApp()
	}
	return true
}

// 参数被刻意忽略：配置由 restartServiceInSequence 以增量方式发布到当前快照上，App.Start 读到的
// 就是它。
func (a *trayApp) startService(*clientconfig.ClientConfig) error { return a.Start() }

// 只能在 session.run 内调用（见 restartServiceInSequence）。
func (a *trayApp) restartService(newCfg *clientconfig.ClientConfig) error {
	return a.restartServiceInSequence(newCfg, a.startService)
}

// 整段停/起持有 session 序列锁，供不持有序列的调用方使用。序列锁不可重入：已在 session.run
// 闭包内的调用方必须直接调用 restartServiceInSequence，否则死锁。
func (a *trayApp) restartServiceWith(newCfg *clientconfig.ClientConfig, start func(*clientconfig.ClientConfig) error) error {
	return a.sess.runErr(func() error {
		return a.restartServiceInSequence(newCfg, start)
	})
}

// 整段在会话序列锁内，退出路径与切换/自更新重启不会交错。
func (a *trayApp) closeService() {
	a.sess.run(a.Close)
}

// restartAfterUpdate 在安装完成后重启进程；失败时恢复服务并把错误交给调用方。
// 与菜单切换服务器属同一类临界区：不共用会话序列锁会让两套停/起交错抢本地端口。
func (a *trayApp) restartAfterUpdate() error {
	var restartErr error
	a.sess.run(func() {
		a.Close()
		// 先释放单例锁，新进程才不会与旧进程竞争单例互斥锁。
		singleton.Release()

		if err := selfupdate.Restart(); err != nil {
			// 新二进制已就位，让旧版本继续运行，由用户手动重启。
			log.Error("[SYSTRAY] restart after update", "err", err)
			// 重新获取单例锁，本进程继续提供服务期间保持唯一实例。
			if lerr := singleton.TryAcquire(); lerr != nil {
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
func (a *trayApp) browserProxyEnabled() bool {
	return a.object.BrowserChecked()
}

func (a *trayApp) setTunMenuChecked(checked bool) {
	a.object.SetTunChecked(checked)
}

func (a *trayApp) startLocalService() {
	if a.object.BrowserChecked() {
		if err := a.setSysProxyOn(sysproxy.Addr(a.currentConfig())); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy on", "err", err)
		}
	} else {
		if err := a.setSysProxyOff(); err != nil {
			log.Error("[SYSTRAY] start local: set sysproxy off", "err", err)
		}
	}

	// 菜单在 App.Start 之前构建，勾选状态可能被启动过程改写；这里按 cfg 双向同步，避免
	// "勾选但未运行"让用户需要点两次才能开启。
	a.object.SetTunChecked(a.currentConfig().Local.EnableTun2socks)
}
