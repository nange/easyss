package app

import (
	"errors"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/runner"
)

// 本文件是"VPN 本会话缺席"这条启动警告的文案与呈现规则。它属于 App 而不是托盘：
// restartServiceInSequence（切换服务器、自更新重启）在 app.go 里，两条启动路径都要
// 用同一份文案，而 headless 构建只是没有界面（a.ui 为 nil）。

// runningServerAddr 返回运行中会话**实际使用**的服务器（host:port）；空表示没有会话。
//
// 读的是会话起点冻结下来的事实（Core.ServerAddr），而不是配置快照里的 default 标记：
// 那个标记表示"用户想用哪台"，切换回滚与自更新重启都会改写它。
func (a *App) runningServerAddr() string {
	core := a.currentCore()
	if core == nil {
		return ""
	}
	return core.ServerAddr
}

// startupWarningNotice 报告该启动警告是否需要立刻以系统通知呈现（false = 只写日志）。
//
// 目前只有一类命中：VPN 本会话缺席，原因是运行中的服务器不在声明的 DERP 中继列表里。
// 其余启动警告保持仅日志：启动路径上已经有通知，网络未就绪的恢复提示另有
// watchServerDomainReady 负责，重复弹窗只会变成噪音。
func startupWarningNotice(warn error) bool {
	return warn != nil && errors.Is(warn, clientconfig.ErrCurrentServerNotDERPRelay)
}

// vpnRefusalText 是"VPN 在本会话不生效"的用户文案。server 必须是运行中会话实际使用的
// 那台（见 runningServerAddr）：用户看到的"VPN 里连不上对端"说的永远是它。
func vpnRefusalText(server string, err error) string {
	where := "当前使用的服务器"
	if server != "" {
		where = "当前使用的服务器 " + server
	}
	return "VPN 功能不生效：" + where + " 不在 vpn 声明的中继(DERP)列表里，节点组网在本会话内不可用，" +
		"VPN 里访问不了任何对端；请在配置文件中给该服务端条目加上 \"derp\": true，" +
		"或切换到已标记为中继的服务器。代理（SOCKS5/HTTP）仍可正常使用。详情：" + err.Error()
}

// startupWarningText 渲染一次会话起点的启动警告：VPN 那条用专用文案，其余沿用
// friendlyStartupWarning。多条警告并存时全部原因都在详情里（StartupWarn 是 errors.Join）。
func (a *App) startupWarningText(warn error) string {
	if startupWarningNotice(warn) {
		return vpnRefusalText(a.runningServerAddr(), warn)
	}
	return friendlyStartupWarning(warn)
}

// notifyStartupWarning 在切换服务器/自更新重启成功之后呈现"必须让用户知道"的那条警告。
// 没有界面时（headless 与 --disable-tray 走不到切换路径）静默返回。
func (a *App) notifyStartupWarning(warn error) {
	if !startupWarningNotice(warn) || a.ui == nil {
		return
	}
	a.ui.notify(a.startupWarningText(warn))
}

// friendlyStartupWarning 渲染非 VPN 的启动警告。服务端域名解析失败是最常见的一类
// （开机自启动时网络往往尚未就绪），它不中止启动。
func friendlyStartupWarning(err error) string {
	if errors.Is(err, runner.ErrServerDomainUnresolved) {
		return "启动警告：网络尚未就绪（服务端域名解析失败），客户端已在后台自动重试，" +
			"网络恢复后即可正常代理。详情：" + err.Error()
	}
	return "启动警告：" + err.Error()
}
