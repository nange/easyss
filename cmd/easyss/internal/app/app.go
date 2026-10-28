package app

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	clientconfig "github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/cmd/easyss/internal/logview"
	"github.com/nange/easyss/v3/cmd/easyss/internal/sysproxy"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tunhelper"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/runner"
)

func sigWait() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	log.Info("[EASYSS-V3] got signal to exit", "signal", <-c)
}

// appUI 是运行期向用户呈现状态的最小界面，nil 表示没有界面。
type appUI interface {
	tunStartFailed(err error)
	notify(msg string)
	serverDomainReady(msg string)
	browserProxyEnabled() bool
	setTunMenuChecked(checked bool)
}

type App struct {
	// 一经发布即不可变，改动一律走 updateConfig 的克隆 + CAS 交换。
	cfg        atomic.Pointer[clientconfig.ClientConfig]
	configFile string

	ui appUI

	// 本进程是否改过系统代理，退出时据此决定是否撤销。
	sysProxyApplied atomic.Bool

	// 本次会话的全部可变状态，锁序见 session.go。
	sess *session

	deps appDeps
}

var coreGen atomic.Uint64

func (a *App) currentCore() *runner.Core { return a.sess.currentCore() }

// 跨 goroutine 读启动警告必须走这里：写入在 session.start 的锁内。
func (a *App) currentStartupWarn() error { return a.sess.startupWarning() }

func New(cfg *clientconfig.ClientConfig, configFile string) *App {
	a := &App{configFile: configFile, deps: defaultAppDeps()}
	a.sess = newSession(a)
	a.adoptConfig(cfg)
	return a
}

// currentConfig 返回不可变的配置快照，读者无需持锁。需要多个字段时先取一次到
// 局部变量，避免读到两次发布之间的混合状态。
func (a *App) currentConfig() *clientconfig.ClientConfig { return a.cfg.Load() }

// adoptConfig 整体发布新快照，发布后调用方不得再改写它。
func (a *App) adoptConfig(cfg *clientconfig.ClientConfig) { a.cfg.Store(cfg) }

// updateConfig 克隆 → 应用 fn → CAS 交换，CAS 失败说明有并发发布，带新克隆重来，
// 因此 fn 必须可重复执行。Clone 是纯值拷贝，不会失败。
func (a *App) updateConfig(fn func(*clientconfig.ClientConfig)) {
	for {
		cur := a.cfg.Load()
		next := &clientconfig.ClientConfig{}
		// 只有零值 App（测试）才没有快照；生产路径由 New 的 adoptConfig 保证非 nil。
		if cur != nil {
			next = cur.Clone()
		}
		fn(next)
		if a.cfg.CompareAndSwap(cur, next) {
			return
		}
	}
}

// 提权相关的哨兵错误：requestElevation 的实现用它区分"用户取消"与"该平台不支持"，
// 前者要告知用户，后者要回落到原地提权。
var (
	errElevationCancelled   = errors.New("elevation cancelled by the user")
	errElevationUnsupported = errors.New("on-demand elevation is not supported on this platform")
)

// appDeps 是可注入的进程级依赖：核心启动器、系统代理开关、日志查看器与提权能力。
type appDeps struct {
	runCore        func(*clientconfig.ClientConfig) (*runner.Core, error)
	sysProxyApply  func(string) error
	sysProxyRevert func() error
	log            logview.Opener
	// isElevated 是"本进程能不能建 TUN 设备"的唯一判据：Windows 只看管理员令牌，
	// darwin/linux 看 root；只有 tunUpAuto 的原地提权路径依赖它。
	isElevated func() bool
	// requestElevation 以管理员权限接管当前实例（Windows 会重启进程，其余平台不支持）。
	requestElevation func(*App) error
}

// env 记录本 App 对桌面会话环境的改动，撤销系统代理时据此恢复发布前的值。
func defaultAppDeps() appDeps {
	env := sysproxy.New()
	return appDeps{
		runCore:          runner.Run,
		sysProxyApply:    env.Enable,
		sysProxyRevert:   env.Disable,
		log:              logview.Default(),
		isElevated:       tunhelper.IsRoot,
		requestElevation: elevateRestart,
	}
}

type serverDomainReadiness interface {
	ServerDomainReady() <-chan struct{}
	Done() <-chan struct{}
}

// canStartTunNow 报告现在能否启用 TUN。未就绪时启用会把系统 DNS 指向本机转发服务器，
// 而解析服务端域名又要先连上服务器，容易形成解析递归；网络没起来时脚本还会缺默认网关。
func canStartTunNow(core serverDomainReadiness) bool {
	if core == nil {
		return true
	}
	ready := core.ServerDomainReady()
	if ready == nil {
		return true
	}
	select {
	case <-ready:
		return true
	default:
		return false
	}
}

// watchServerDomainReady 在降级启动后等后台重试成功并通知用户一次。pending 为 false 时
// 不派发 goroutine，否则每次正常启动都会弹一条无意义通知。
func (a *App) watchServerDomainReady(core serverDomainReadiness, gen uint64, pending, tunSkipped bool) {
	if !pending || core == nil || a.ui == nil {
		return
	}
	ready, done := core.ServerDomainReady(), core.Done()
	if ready == nil || done == nil {
		return
	}

	go func() {
		select {
		case <-ready:
		case <-done:
			return
		}
		// 就绪与"核心被停止/替换"可能并发发生，过期核心不再弹通知。
		select {
		case <-done:
			return
		default:
		}
		if coreGen.Load() != gen {
			return
		}

		msg := "网络已恢复，代理服务已就绪"
		if tunSkipped {
			msg += "；系统全局流量(Tun2socks)启动时已跳过，可在托盘菜单中重新开启"
		}
		a.ui.serverDomainReady(msg)
	}()
}

func (a *App) Start() error { return a.sess.start() }

// Stop 按"撤销系统代理 → 拆 TUN → 停核心"退出；TUN 依赖核心的本地代理入口。
func (a *App) Stop() {
	a.teardownSysProxy()

	// 先拆 TUN 再停核心，拆除问题由 tunDown 自己记录。
	a.sess.tunDown()

	a.sess.stop()
}

// Close 是托盘的退出/切换入口：与 Stop 的区别是无条件撤销系统代理，用于清理上一次
// 运行或异步开关留下的、可能指向本地端口的代理。
func (a *App) Close() {
	if err := a.setSysProxyOff(); err != nil {
		log.Error("[EASYSS-V3] close: set sysproxy off", "err", err)
	}
	a.Stop()
}

// restartServiceInSequence 只把目标服务器下标这一条增量写回当前快照：Close 可能持续
// 数秒，期间发布停服务前的全量快照会把用户刚改的规则/日志级别静默还原。
func (a *App) restartServiceInSequence(newCfg *clientconfig.ClientConfig, start func(*clientconfig.ClientConfig) error) error {
	targetIdx := newCfg.DefaultServerIndex()

	snap := a.currentConfig()
	prevIdx, prevTun := snap.DefaultServerIndex(), snap.Local.EnableTun2socks

	sysProxyEnabled := a.browserProxyEnabled()

	// macOS 上会提示输入管理员凭据。
	a.Close()

	// 停完之后才发布，只改两项：CAS 会把停服务期间的菜单改动合并进来。
	a.updateConfig(func(c *clientconfig.ClientConfig) {
		c.SetDefaultServerIndex(targetIdx)
		c.Local.EnableTun2socks = false
	})
	a.setTunMenuChecked(false)

	restoreSysProxy := func() {
		if !sysProxyEnabled {
			return
		}
		if err := a.setSysProxyOn(sysproxy.Addr(a.currentConfig())); err != nil {
			log.Error("[EASYSS-V3] restart service: restore sysproxy on", "err", err)
		}
	}

	if err := start(a.currentConfig()); err != nil {
		// 回滚同样只回退这两项；也失败时两个错误一起上报，表示完全没有服务在运行。
		a.updateConfig(func(c *clientconfig.ClientConfig) {
			c.SetDefaultServerIndex(prevIdx)
			c.Local.EnableTun2socks = prevTun
		})
		a.setTunMenuChecked(prevTun)
		prevAddr := a.currentConfig().DefaultServerAddr()
		if rollbackErr := start(a.currentConfig()); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback to %s: %w", prevAddr, rollbackErr))
		}
		log.Warn("[EASYSS-V3] restart service: rolled back to the previous server",
			"addr", prevAddr, "err", err)
		restoreSysProxy()
		return err
	}

	// 与那次 Start 分属不同 goroutine，必须走访问器读启动警告。
	if warn := a.currentStartupWarn(); warn != nil {
		log.Warn("[EASYSS-V3] restart service: startup warning", "err", warn)
	}

	restoreSysProxy()
	return nil
}

func (a *App) browserProxyEnabled() bool {
	return a.ui != nil && a.ui.browserProxyEnabled()
}

func (a *App) setTunMenuChecked(checked bool) {
	if a.ui != nil {
		a.ui.setTunMenuChecked(checked)
	}
}

func (a *App) notifyTunSkippedNoRoot() {
	a.notifyTunSkipped("Tun2socks 未启用：需要管理员权限；请在托盘菜单「代理对象 → 系统全局流量」中开启，届时会请求管理员授权")
}

func (a *App) notifyTunSkippedNetworkUnready() {
	a.notifyTunSkipped("网络尚未就绪：已跳过系统全局流量(Tun2socks)；网络恢复后请在托盘菜单中重新开启")
}

func (a *App) notifyTunSkipped(msg string) {
	if a.ui == nil {
		return
	}
	a.ui.notify(msg)
}

// 残留的分流默认路由会把全机流量黑洞掉，这种状态必须让用户知道。
func (a *App) notifyTunTeardownProblem(msg string) {
	if a.ui == nil {
		log.Warn("[EASYSS-V3] notify skipped: no ui", "msg", msg)
		return
	}
	a.ui.notify(msg)
}

// setupSysProxy 按配置把系统代理指向本地 HTTP 代理，返回是否改动。设置失败只记警告、
// 不使启动失败：root/systemd 下 gsettings 与用户会话总线常常不可达。
func (a *App) setupSysProxy() bool {
	cfg := a.currentConfig()
	if cfg.Local.DisableSysProxy || cfg.Local.HTTPPort <= 0 {
		return false
	}
	if err := a.setSysProxyOn(sysproxy.Addr(cfg)); err != nil {
		log.Warn("[EASYSS-V3] set system proxy failed, you may need to configure it manually", "err", err)
		return false
	}
	return true
}

// 只在 sysProxyApplied 为真时撤销，重复调用无副作用。
func (a *App) teardownSysProxy() {
	if !a.sysProxyApplied.Swap(false) {
		return
	}
	if err := a.deps.sysProxyRevert(); err != nil {
		log.Warn("[EASYSS-V3] unset system proxy failed, you may need to restore it manually", "err", err)
	}
}

func (a *App) setSysProxyOn(addr string) error {
	err := a.deps.sysProxyApply(addr)
	if err == nil {
		a.sysProxyApplied.Store(true)
	}
	return err
}

func (a *App) setSysProxyOff() error {
	err := a.deps.sysProxyRevert()
	if err == nil {
		a.sysProxyApplied.Store(false)
	}
	return err
}

func (a *App) methodFromServer() protocol.Method {
	method := protocol.MethodFromString(a.currentConfig().DefaultServer().Method)
	if method == 0 {
		method = protocol.MethodAES256GCM
	}
	return method
}

// tunDNS 是 TUN 模式下写入系统的解析器。与 enable_forward_dns 无关：转发服务器监听
// 0.0.0.0:53 供 LAN 使用，把本机解析器指向它只会绕一圈并丢掉按域名拆分的路径。
func tunDNS() string {
	return easydns.PreferredSystemDNS()
}
