package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	_ "time/tzdata"

	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/version"
)

func main() {
	// "selfupdate" 与 "tun-helper" 必须在 flag 解析前分流，否则参数会与代理参数冲突。
	if runSelfupdateSubcommand() {
		return
	}
	if runTunHelperSubcommand() {
		return
	}

	var printVer, showConfigExample, showConfigExampleSimple, daemon, disableTray, enableTun2socks bool
	var configFile, cmdOutboundProto string
	var pprofEnabled bool
	var logFile string

	sc := &sharedconfig.SimpleConfig{}

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file (full mode)")
	flag.BoolVar(&showConfigExampleSimple, "show-config-example-simple", false, "show a example of config file (simple mode)")
	flag.StringVar(&sc.Server, "s", "", "server host (domain or IP, without port)")
	flag.IntVar(&sc.ServerPort, "p", 0, "server port")
	flag.StringVar(&sc.Password, "k", "", "password")
	flag.StringVar(&sc.Method, "m", "", "encryption method (aes-256-gcm, chacha20-poly1305)")
	flag.StringVar(&sc.ProxyRule, "proxy-rule", "", "proxy rule (auto, reverse_auto, proxy, direct, auto_block)")
	flag.StringVar(&cmdOutboundProto, "outbound-proto", "", "outbound protocol (native, h2)")
	flag.IntVar(&sc.LocalPort, "l", 0, "local socks5 port")
	flag.IntVar(&sc.Timeout, "t", 0, "timeout in seconds (clamped to 15-60, the base of all derived timeouts)")
	flag.StringVar(&sc.LogLevel, "log-level", "", "log level (debug, info, warn, error)")
	flag.StringVar(&logFile, "log-file", "", "log file path")
	flag.BoolVar(&sc.EnableQUIC, "enable-quic", false, "enable QUIC protocol")
	flag.StringVar(&sc.SN, "sn", "", "TLS SNI override")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.BoolVar(&daemon, "daemon", runtime.GOOS != "windows", "run app as daemon")
	flag.BoolVar(&disableTray, "disable-tray", false, "disable system tray (windows/mac only)")
	flag.BoolVar(&enableTun2socks, "enable-tun2socks", false, "enable tun2socks model")
	flag.StringVar(&sc.IPV6Rule, "ipv6-rule", "", "set the ipv6 rule(auto, enable, disable), default: auto")
	flag.StringVar(&sc.DirectFile, "direct-file", "", "custom direct file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
	flag.StringVar(&sc.ProxyFile, "proxy-file", "", "custom proxy file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
	flag.BoolVar(&pprofEnabled, "pprof", false, "enable pprof debug server on :6060")

	flag.Usage = func() {
		bin := filepath.Base(os.Args[0])
		out := flag.CommandLine.Output()
		_, _ = fmt.Fprintf(out, `Easyss - SOCKS5/HTTP 代理客户端

用法:
  %s [flags]              启动代理（托盘版默认带系统托盘，可用 --disable-tray 关闭）
  %s selfupdate [flags]   检查并升级到最新 release
  %s tun-helper [flags]   内部：以提权 TUN 助手模式运行（由主程序自动拉起）

子命令:
  selfupdate    从 GitHub 检查最新 release，并原地替换当前二进制（不自动重启）。
                更新完成后请手动重启进程使新版本生效。支持 --check（仅检查）、
                --version <tag>（安装指定版本，可重装当前版本或回退，tag 需与
                release tag 完全一致）、--proxy-port（走本地代理下载）。
  tun-helper    内部子命令：打开 TUN 设备、配置路由/DNS 并把 fd 传回主进程，
                由主程序在提权场景下自动拉起，请勿手动使用。支持
                --tun-http-addr/--tun-fd-socket/--log-file/--log-level。

Flags:
`, bin, bin, bin)
		flag.PrintDefaults()
	}

	flag.Parse()

	if printVer {
		version.Print()
		os.Exit(0)
	}
	if showConfigExample {
		fmt.Println(exampleV3Config())
		os.Exit(0)
	}
	if showConfigExampleSimple {
		fmt.Println(exampleSimpleConfig())
		os.Exit(0)
	}

	configFile = util.ResolvePath(configFile)

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		if sc.Server != "" && sc.Password != "" {
			cfg, err = config.BuildSimpleConfig(sc)
			if err != nil {
				log.Error("[EASYSS-V3] build config from args", "err", err)
				if !disableTray {
					notifyConfigError(err)
				}
				os.Exit(1)
			}
		} else {
			log.Error("[EASYSS-V3] load config", "err", err)
			if !disableTray {
				notifyConfigError(err)
			}
			os.Exit(1)
		}
	} else if err := config.ApplySimpleOverrides(cfg, sc); err != nil {

		log.Error("[EASYSS-V3] apply simple overrides", "err", err)
		if !disableTray {
			notifyConfigError(err)
		}
		os.Exit(1)
	}

	// 相对路径按可执行文件目录解析，launchd 启动（cwd=/）时才找得到。
	cfg.ResolveFilePaths()

	if cfg.Log.FilePath != "" && !filepath.IsAbs(cfg.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			cfg.Log.FilePath = filepath.Join(dir, cfg.Log.FilePath)
		}
	}

	log.Info("[EASYSS-V3] set log-level", "level", cfg.Log.Level)
	log.Init(cfg.Log.FilePath, cfg.Log.Level)
	log.Info("[EASYSS-V3] " + version.String())

	// 须在 log.Init 之后，清理日志才写到配置的输出而不是 GUI 中不可见的 stdout。
	selfupdate.CleanupOld()

	// 转成绝对路径，提权助手进程无论 cwd 如何都能找到配置。
	if !filepath.IsAbs(configFile) {
		if abs, err := filepath.Abs(configFile); err == nil {
			configFile = abs
		}
	}

	if enableTun2socks {
		cfg.Local.EnableTun2socks = true
	}
	if cmdOutboundProto != "" {
		proto, err := config.OutboundProtoToProtocol(cmdOutboundProto)
		if err != nil {
			log.Error("[EASYSS-V3] invalid outbound-proto", "value", cmdOutboundProto, "err", err)
			os.Exit(1)
		}
		cfg.Transport.Protocol = proto
	}
	if pprofEnabled {
		cfg.PprofEnabled = true
	}

	log.Info("[EASYSS-V3] config loaded",
		"config_file", configFile,
		"server", cfg.DefaultServerAddr(),
		"socks_port", cfg.Local.SocksPort,
		"http_port", cfg.Local.HTTPPort,
		"proxy_rule", cfg.Routing.ProxyRule,
		"ipv6_rule", cfg.Routing.IPV6Rule,
		"timeout", cfg.Timeout,
		"conn_lifetime", cfg.ConnLifetimeDuration(),
		"direct_file", cfg.Routing.DirectFile,
		"proxy_file", cfg.Routing.ProxyFile,
	)

	app := newApp(cfg, configFile)
	runApp(disableTray, daemon, app)
}

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
	cfg        atomic.Pointer[config.ClientConfig]
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

func newApp(cfg *config.ClientConfig, configFile string) *App {
	a := &App{configFile: configFile, deps: defaultAppDeps()}
	a.sess = newSession(a)
	a.adoptConfig(cfg)
	return a
}

// currentConfig 返回不可变的配置快照，读者无需持锁。需要多个字段时先取一次到
// 局部变量，避免读到两次发布之间的混合状态。
func (a *App) currentConfig() *config.ClientConfig { return a.cfg.Load() }

// adoptConfig 整体发布新快照，发布后调用方不得再改写它。
func (a *App) adoptConfig(cfg *config.ClientConfig) { a.cfg.Store(cfg) }

// updateConfig 克隆 → 应用 fn → CAS 交换，CAS 失败说明有并发发布，带新克隆重来，
// 因此 fn 必须可重复执行。
func (a *App) updateConfig(fn func(*config.ClientConfig)) {
	for {
		cur := a.cfg.Load()
		var next *config.ClientConfig
		if cur == nil {
			next = &config.ClientConfig{}
		} else if next = cur.Clone(); next == nil {
			// 保留旧快照：把 nil 发布出去会让所有读者解引用它。
			log.Error("[EASYSS-V3] update config: clone failed, keeping the current snapshot")
			return
		}
		fn(next)
		if a.cfg.CompareAndSwap(cur, next) {
			return
		}
	}
}

// appDeps 是可注入的进程级依赖：核心启动器、系统代理开关与日志查看器。
type appDeps struct {
	runCore        func(*config.ClientConfig) (*runner.Core, error)
	sysProxyApply  func(string) error
	sysProxyRevert func() error
	log            logOpener
}

func defaultAppDeps() appDeps {
	return appDeps{
		runCore:        runner.Run,
		sysProxyApply:  setSysProxy,
		sysProxyRevert: unsetSysProxy,
		log:            defaultLogOpener(),
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
func (a *App) restartServiceInSequence(newCfg *config.ClientConfig, start func(*config.ClientConfig) error) error {
	targetIdx := newCfg.DefaultServerIndex()

	snap := a.currentConfig()
	prevIdx, prevTun := snap.DefaultServerIndex(), snap.Local.EnableTun2socks

	sysProxyEnabled := a.browserProxyEnabled()

	// macOS 上会提示输入管理员凭据。
	a.Close()

	// 停完之后才发布，只改两项：CAS 会把停服务期间的菜单改动合并进来。
	a.updateConfig(func(c *config.ClientConfig) {
		c.SetDefaultServerIndex(targetIdx)
		c.Local.EnableTun2socks = false
	})
	a.setTunMenuChecked(false)

	restoreSysProxy := func() {
		if !sysProxyEnabled {
			return
		}
		if err := a.setSysProxyOn(sysProxyAddr(a.currentConfig())); err != nil {
			log.Error("[EASYSS-V3] restart service: restore sysproxy on", "err", err)
		}
	}

	if err := start(a.currentConfig()); err != nil {
		// 回滚同样只回退这两项；也失败时两个错误一起上报，表示完全没有服务在运行。
		a.updateConfig(func(c *config.ClientConfig) {
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
	a.notifyTunSkipped("Tun2socks 未启用：需要管理员权限，请以 root 运行或使用系统托盘授权")
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
	if err := a.setSysProxyOn(sysProxyAddr(cfg)); err != nil {
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

func exampleV3Config() string {
	cfg := config.ClientConfig{
		ConfigVersion: 3,
		Servers: []*config.ServerProfile{{
			Host:     "your-domain.com",
			Port:     sharedconfig.DefaultServerPort,
			Password: "your-password",
			Method:   sharedconfig.DefaultMethod,
			SNI:      "",
			CAPath:   "",
			Default:  true,
		}},
		// 示例不走 applyDefaults，http_port 按同一规则显式给出。
		Local: config.LocalConfig{
			SocksPort:        sharedconfig.DefaultSocksPort,
			HTTPPort:         sharedconfig.DefaultSocksPort + sharedconfig.DefaultHTTPPortOffset,
			BindAll:          false,
			DisableSysProxy:  false,
			EnableForwardDNS: false,
			EnableTun2socks:  false,
			EnableQUIC:       false,
			TunMTU:           sharedconfig.DefaultTunMTU,
		},
		Routing: config.RoutingConfig{
			ProxyRule:  sharedconfig.DefaultProxyRule,
			IPV6Rule:   sharedconfig.DefaultIPV6Rule,
			DirectFile: "",
			ProxyFile:  "",
		},
		Transport: config.TransportConfig{
			Protocol:          sharedconfig.DefaultProtocol,
			ConnCountMax:      sharedconfig.DefaultConnCountMax,
			StreamThreshold:   sharedconfig.DefaultStreamThreshold,
			PrioritySlotRatio: sharedconfig.DefaultPrioritySlotRatio,
			ConnMaxBytes:      sharedconfig.DefaultConnMaxBytes,
		},
		Shaper: config.ShaperConfig{
			BatchWindowMS:    sharedconfig.DefaultBatchWindowMS,
			CoverBudgetRatio: sharedconfig.DefaultCoverBudgetRatio,
			CoverBudgetCap:   sharedconfig.DefaultCoverBudgetCap,
		},
		Log: config.LogConfig{
			Level:    sharedconfig.DefaultLogLevel,
			FilePath: "easyss.log",
		},
		Timeout:      sharedconfig.DefaultTimeout,
		AuthUsername: "",
		AuthPassword: "",
		PprofEnabled: false,
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

func exampleSimpleConfig() string {
	cfg := sharedconfig.SimpleConfig{
		Server:        "your-domain.com",
		ServerPort:    sharedconfig.DefaultServerPort,
		Password:      "your-password",
		Method:        sharedconfig.DefaultMethod,
		LocalPort:     sharedconfig.DefaultSocksPort,
		ProxyRule:     sharedconfig.DefaultProxyRule,
		Timeout:       sharedconfig.DefaultTimeout,
		BindAll:       false,
		OutboundProto: "native",
		DirectFile:    "",
		ProxyFile:     "",
		LogLevel:      sharedconfig.DefaultLogLevel,
		LogFilePath:   "easyss.log",
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}
