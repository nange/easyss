package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/tun"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/pprof"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/version"
)

func main() {
	// "selfupdate" 和 "tun-helper" 子命令在 flag 解析之前处理，
	// 这样它们永远不会与代理参数冲突。selfupdate 会替换当前运行的二进制并退出；
	// tun-helper 则以提权 TUN 助手模式运行本二进制（由托盘进程内部拉起）并退出。
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
	flag.StringVar(&sc.Server, "s", "", "server address")
	flag.IntVar(&sc.ServerPort, "p", 0, "server port")
	flag.StringVar(&sc.Password, "k", "", "password")
	flag.StringVar(&sc.Method, "m", "", "encryption method (aes-256-gcm, chacha20-poly1305)")
	flag.StringVar(&sc.ProxyRule, "proxy-rule", "", "proxy rule (auto, reverse_auto, proxy, direct, auto_block)")
	flag.StringVar(&cmdOutboundProto, "outbound-proto", "", "outbound protocol (native, h2)")
	flag.IntVar(&sc.LocalPort, "l", 0, "local socks5 port")
	flag.IntVar(&sc.Timeout, "t", 0, "timeout in seconds")
	flag.StringVar(&sc.LogLevel, "log-level", "", "log level (debug, info, warn, error)")
	flag.StringVar(&logFile, "log-file", "", "log file path")
	flag.BoolVar(&sc.EnableQUIC, "enable-quic", false, "enable QUIC protocol")
	flag.BoolVar(&sc.DisableWarmUp, "disable-warmup", false, "disable the background warm-up of the transport connection pools")
	flag.StringVar(&sc.SN, "sn", "", "TLS SNI override")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.BoolVar(&daemon, "daemon", runtime.GOOS != "windows", "run app as daemon")
	flag.BoolVar(&disableTray, "disable-tray", false, "disable system tray (windows/mac only)")
	flag.BoolVar(&enableTun2socks, "enable-tun2socks", false, "enable tun2socks model")
	flag.StringVar(&sc.IPV6Rule, "ipv6-rule", "", "set the ipv6 rule(auto, enable, disable), default: auto")
	flag.StringVar(&sc.DirectFile, "direct-file", "", "custom direct file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
	flag.StringVar(&sc.ProxyFile, "proxy-file", "", "custom proxy file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
	flag.BoolVar(&pprofEnabled, "pprof", false, "enable pprof debug server on :6060")

	// 自定义 usage，使 --help/-h 也能介绍 "selfupdate" 和 "tun-helper"
	// 子命令——它们在 flag 解析之前处理，否则在帮助中不可见。
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
                --proxy-port（走本地代理下载）。
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

	// 在 macOS 上应用常由 Finder/launchd 以 cwd=/ 启动，
	// 因此相对配置文件路径会先在工作目录查找，再回退到可执行文件所在目录。
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
	} else {
		config.ApplySimpleOverrides(cfg, sc)
	}

	// 将相对文件路径（direct_file/proxy_file/ca_path）相对于可执行文件目录解析，
	// 这样 macOS Finder/launchd 启动（cwd=/）时仍能找到放在二进制/.app 包旁边的文件。
	cfg.ResolveFilePaths()

	if cfg.Log.FilePath != "" && !filepath.IsAbs(cfg.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			cfg.Log.FilePath = filepath.Join(dir, cfg.Log.FilePath)
		}
	}

	log.Info("[EASYSS-V3] set log-level", "level", cfg.Log.Level)
	log.Init(cfg.Log.FilePath, cfg.Log.Level)
	log.Info("[EASYSS-V3] " + version.String())

	// 清理上次自更新遗留的文件（为 Windows/macOS 保留的重命名旧二进制、过期的暂存目录）。
	// 在 log.Init 之后执行，这样其日志会写入配置的输出，而不是默认的 stdout 处理器
	//（GUI 构建中 stdout 不可见）。
	selfupdate.CleanupOld()

	// 将配置文件路径改为绝对路径，这样任何提权助手进程
	// 无论工作目录如何都能找到它。
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
		"direct_file", cfg.Routing.DirectFile,
		"proxy_file", cfg.Routing.ProxyFile,
	)

	app := &App{cfg: cfg, configFile: configFile}
	runApp(disableTray, daemon, app)
}

func sigWait() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	log.Info("[EASYSS-V3] got signal to exit", "signal", <-c)
}

type App struct {
	cfg        *config.ClientConfig
	configFile string // 配置文件绝对路径
	core       *runner.Core
	tunMgr     *tun.Manager
	pprofSrv   *http.Server

	// startupWarn 记录首个非致命启动警告（例如服务端域名解析失败，
	// 或自定义规则文件加载失败）。客户端继续运行；托盘以系统通知形式
	// 呈现，headless 构建则记入日志。
	startupWarn error

	// tunSkippedForNetwork 记录启动时因服务端域名尚未解析成功（开机网络还
	// 没就绪）而跳过了 TUN；后台解析恢复后据此在通知里提醒用户手动开启。
	tunSkippedForNetwork bool

	// statsCloser 用于停止后台统计日志器。它由 statsMu 保护，
	// 因为 Start/Stop 可能并发执行（托盘菜单处理器），
	// 而且 Start 失败时会保持未设置：关闭 nil channel 会 panic。
	statsMu     sync.Mutex
	statsCloser chan struct{}
}

// coreGen 为每次 App.Start 启动的核心分配单调递增的序号，供后台 goroutine
// 判断自己观察的核心是否仍是当前核心。App 会被 restartService 整体重建
// （*a.App = App{...}），因此序号不能放在 App 上，否则会与旧实例冲突。
var coreGen atomic.Uint64

// serverDomainReadyNotify 非 nil 时，通过托盘系统通知报告"后台重试已解析出
// 服务端域名、代理恢复可用"。托盘构建在 buildTray 中安装它；headless 与
// --disable-tray 构建保持 nil，此时恢复过程只体现在日志里（由 runner 输出）。
var serverDomainReadyNotify func(msg string)

// serverDomainReadiness 是启动路径需要的最小核心视图：服务端域名是否已就绪，
// 以及核心何时停止。抽成接口是为了能在测试中注入假实现
// （*runner.Core 的字段无法从包外构造）。
type serverDomainReadiness interface {
	ServerDomainReady() <-chan struct{}
	Done() <-chan struct{}
}

// canStartTunNow 报告现在是否可以启用 TUN：服务端域名必须已经解析成功
// （或无需解析）。nil core 与未初始化的就绪通道都视为"无需等待"，保持既有行为。
//
// 未就绪时启用 TUN 是危险的：平台脚本会把系统 DNS 指向本机转发服务器，
// 而解析服务端域名又需要先连上服务器（隧道），容易形成解析递归；网络根本
// 没起来时脚本还会因缺默认网关而失败。
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

// watchServerDomainReady 在降级启动（服务端域名暂不可解析）后，等待后台重试
// 成功并向用户报告一次。pending 为 false（启动即就绪）时不派发任何 goroutine，
// 否则每次正常启动都会弹一条无意义通知。tunSkipped 由调用方在派发前读取，
// 使 goroutine 不必访问会被 restartService 重建的 App 字段。
func (a *App) watchServerDomainReady(core serverDomainReadiness, gen uint64, pending, tunSkipped bool) {
	if !pending || core == nil || serverDomainReadyNotify == nil {
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
		// 就绪与"核心被停止/替换"可能并发发生：过期核心不再弹通知。
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
		serverDomainReadyNotify(msg)
	}()
}

func (a *App) Start() error {
	core, err := runner.Run(a.cfg)
	if err != nil {
		return err
	}
	a.core = core
	a.setStartupWarn(core.StartupWarn)
	gen := coreGen.Add(1)
	// 降级启动（开机时网络未就绪、服务端域名暂不可解析）时为 true。
	domainPending := !canStartTunNow(core)

	if a.cfg.Local.EnableTun2socks {
		// 在 macOS 和 Linux 非 root 环境下，TUN 通过提权启动（助手进程或以 root 重启）。
		// 这里跳过直接创建，以避免 "operation not permitted"。到达该分支意味着
		// 用户请求了系统全局流量但无法获得，因此托盘会告知原因，
		// 而不是留下一个静默未代理的系统。main.go 与 headless 构建共享，
		// 所以这里通过 tunStartNotify 而非直接使用托盘。
		if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && !IsRoot() {
			log.Warn("[EASYSS-V3] tun2socks requires root; skipped (use sudo, or run with system tray for automatic elevation)")
			notifyTunSkippedNoRoot()
		} else if !domainPending {
			// runner.Run 已确保服务端主机名可解析并预填充了 DNS 缓存
			//（resolveServerDomain），因此 TUN 模式的 DNS 永远不会在服务端域名上死锁。
			a.startTunEngineAtStartup()
		} else {
			// 开机时网络常常尚未就绪，服务端域名还没解析出来。此时照常启用 TUN
			// 会让平台脚本把系统 DNS 指向本机转发服务器，而解析服务端域名又需要
			// 隧道本身（递归）；网络根本没起来时脚本还会因缺默认网关失败。
			// 因此跳过 TUN，并把配置与托盘勾选同步为"未启用"，等网络恢复后由
			// 用户手动开启（届时 canStartTunNow 放行）。
			a.cfg.Local.EnableTun2socks = false
			a.tunSkippedForNetwork = true
			log.Warn("[EASYSS-V3] server domain not resolved yet; tun2socks skipped until the network is ready")
			notifyTunSkippedNetworkUnready()
		}
	}

	a.startStatsLoop()

	if a.cfg.PprofEnabled {
		a.pprofSrv = pprof.StartPprof()
	}

	// 降级启动时，网络恢复后向用户报告一次（仅托盘构建安装了 hook）。
	a.watchServerDomainReady(core, gen, domainPending, a.tunSkippedForNetwork)

	return nil
}

// startTunEngineAtStartup 在启动路径上创建 TUN 管理器并派发引擎启动。
// 构造顺序与托盘菜单路径（TrayApp.createTun2socks）保持一致。
func (a *App) startTunEngineAtStartup() {
	a.tunMgr = tun.New(a.tunConfig())

	icmpHandler := tun.NewICMPHandler(a.core.Client.Router())
	icmpHandler.SetProxy(a.core.StreamHandler, a.methodFromServer())
	a.tunMgr.SetICMPHandler(icmpHandler)

	startTunEngine(a.tunMgr, "device")
}

// notifyTunSkippedNetworkUnready 报告 TUN 因服务端域名尚未解析成功而跳过。
// 与 notifyTunSkippedNoRoot 一样走 tunStartNotify：headless 与 --disable-tray
// 构建没有托盘 hook，原因只写日志。
func notifyTunSkippedNetworkUnready() {
	if tunStartNotify != nil {
		tunStartNotify("网络尚未就绪：已跳过系统全局流量(Tun2socks)；网络恢复后请在托盘菜单中重新开启")
	}
}

// tunStartFailureHook 非 nil 时，会在 TUN 引擎启动失败后执行。
// 托盘构建在 buildTray 中安装它，这样启动时的失败也会回滚菜单项
// （见 (*TrayApp).revertTunStart）。headless 和 --disable-tray 构建保持其为 nil：
// 它们没有可回滚的 UI 状态，引擎由 Stop() 释放。它只被 trayStartTunFailure 调用，
// 后者还会向用户报告失败原因。
var tunStartFailureHook func()

// tunStartNotify 非 nil 时，通过托盘的系统通知向用户报告 TUN 启动失败。
// 托盘构建在 buildTray 中安装它（见 (*TrayApp).notifyTunStartFailure）；
// headless 和 --disable-tray 构建保持其为 nil，因此原因只会写入日志文件。
// 没有它，失败将不可见：代理核心继续运行，只是用户刚开启的状态
// （系统全局流量）缺失。
var tunStartNotify func(msg string)

// tunStartErrorText 非 nil 时，将 TUN 启动错误转换为展示给用户的消息，
// 对用户有意造成的失败可返回空字符串（见 tray.go 中的 friendlyTunError，
// 在 buildTray 中安装）。在 headless 和 --disable-tray 构建中保持为 nil，
// 此时 trayStartTunFailure 回退到 err.Error() —— main.go 被编译进每个构建，
// 无法引用 tray.go。
//
// 当前值在引擎 goroutine 上读取，因此只在启动期间、任何引擎启动可能失败之前
// 写入一次。
var tunStartErrorText func(err error) string

// startTunEngine 在后台启动 tun2socks 引擎。Manager.Start
// 会阻塞至设备设置、稳定等待延迟和平台路由脚本完成（最长 60 秒），
// 因此不能放在调用方 goroutine 上运行。
//
// mode 表示设备获取方式（"device" 表示按名称、"fd" 表示来自提权助手），
// 以便失败可追溯到两条路径之一。
//
// 上游把启动失败作为错误返回，而不是像过去那样用 log.Fatalf 杀死进程
// （tun2socks #550/#552），因此半启用状态必须由其持有者撤销，而不是靠退出进程。
func startTunEngine(mgr *tun.Manager, mode string) {
	go func() {
		if err := mgr.Start(); err != nil {
			log.Error("[EASYSS-V3] tun2socks start", "mode", mode, "err", err)
			trayStartTunFailure(err)
		}
	}()
}

// trayStartTunFailure 是"TUN 引擎启动失败"的唯一处理者：
// 它回滚半启用状态（hook）并向用户说明原因（notify）。
//
// tunStartErrorText 对用户主动要求而非被动承受的失败可返回空消息
// （见 friendlyTunError）：Stop() 取消启动 —— 关闭开关、切换服务器、退出应用 ——
// 都不值得为此打扰用户。这种情况下回滚仍会执行：无论谁停止了什么，
// 菜单最终都必须处于未勾选状态。
func trayStartTunFailure(err error) {
	if tunStartFailureHook != nil {
		tunStartFailureHook()
	}
	if err == nil {
		return
	}
	msg := err.Error()
	if tunStartErrorText != nil {
		msg = tunStartErrorText(err)
	}
	if msg != "" && tunStartNotify != nil {
		tunStartNotify(msg)
	}
}

// notifyTunSkippedNoRoot 报告 TUN 已配置但因缺少管理员权限而无法启动。
// 提示文本是固定的：没有可附加的底层错误，而且可操作的建议在
// 到达该路径的所有平台上都一样。
func notifyTunSkippedNoRoot() {
	if tunStartNotify != nil {
		tunStartNotify("Tun2socks 未启用：需要管理员权限，请以 root 运行或使用系统托盘授权")
	}
}

// setStartupWarn 记录首个非致命启动警告。客户端继续运行；
// 托盘以系统通知形式呈现，headless 构建则记入日志。
func (a *App) setStartupWarn(err error) {
	if err == nil || a.startupWarn != nil {
		return
	}
	a.startupWarn = err
	log.Warn("[EASYSS-V3] startup warning", "err", err)
}

func (a *App) Stop() {
	a.stopStatsLoop()

	if a.tunMgr != nil {
		a.tunMgr.Stop()
	}
	if a.core != nil {
		a.core.Stop()
	}
	if a.pprofSrv != nil {
		pprof.StopPprof(a.pprofSrv)
	}
}

// startStatsLoop（重新）启动后台统计日志器，若之前的循环仍在运行则将其停止。
// 停止 channel 被 goroutine 捕获，因此后续重启不会让旧循环在新 channel 上 select。
func (a *App) startStatsLoop() {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	if a.statsCloser != nil {
		close(a.statsCloser)
	}
	a.statsCloser = make(chan struct{})
	go a.statsLoop(a.statsCloser)
}

// stopStatsLoop 停止后台统计日志器。对从未启动过统计日志器的 App 调用是安全的，
// 重复调用也是安全的。
func (a *App) stopStatsLoop() {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	if a.statsCloser != nil {
		close(a.statsCloser)
		a.statsCloser = nil
	}
}

func (a *App) statsLoop(done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if a.core == nil || a.core.Client == nil {
				continue
			}
			snap := stats.Collect()
			snap.TransportStats = a.core.Client.Transport().Stats()
			log.Info("[STATS]",
				"uptime", snap.Uptime().Round(time.Second),
				"conns", snap.Conns,
				"priority_conns", snap.PriorityConns,
				"bulk_conns", snap.BulkConns,
				"priority_conns_status", snap.PriorityConnsStatus,
				"bulk_conns_status", snap.BulkConnsStatus,
				"active_streams", snap.ActiveStreams,
				"priority_active", snap.PriorityActiveStreams,
				"bulk_active", snap.BulkActiveStreams,
				"streams(opened)", snap.TotalStreamsOpened,
				"streams(closed)", snap.TotalStreamsClosed,
				"priority_opened", snap.PriorityStreamsOpened,
				"bulk_opened", snap.BulkStreamsOpened,
				"priority_fallback", snap.PriorityFallback,
				"bulk_fallback", snap.BulkFallback,
				"tx", stats.HumanBytes(snap.BytesSent),
				"rx", stats.HumanBytes(snap.BytesRecv),
				"raw_tx", stats.HumanBytes(snap.RawBytesSent),
				"raw_rx", stats.HumanBytes(snap.RawBytesRecv),
				"upload_speed", snap.UploadSpeedHuman,
				"download_speed", snap.DownloadSpeedHuman,
				"proxy_tcp_streams", snap.TCPConnections,
				"udp_assoc", snap.UDPAssociations,
				"dns(hit)", snap.DNSCacheHits,
				"dns(miss)", snap.DNSCacheMisses,
				"dns(proxy)", snap.DNSProxyQueries,
				"dns(direct)", snap.DNSDirectQueries,
				"padding", stats.HumanBytes(snap.PaddingBytes),
				"records", snap.RecordsWritten,
				"avg_rtt", snap.AvgRTT().Round(time.Millisecond),
				"slot_degraded", snap.SlotDegraded,
				"slot_retired_degraded", snap.SlotRetiredDegraded,
				"slot_probes", snap.SlotProbes,
				"slot_probe_slow", snap.SlotProbeSlow,
				"slot_grown_priority", snap.SlotGrownPriority,
				"slot_grown_bulk", snap.SlotGrownBulk,
				"conn_rotated", snap.ConnRotated,
			)
		case <-done:
			return
		}
	}
}

// tunConfig 为本 App 构建 TUN 配置。它是启动路径与托盘开关共享的唯一构造点，
// 因此两者不会出现偏差（尤其是 server-IPv6 提示，托盘路径过去常常遗漏它）。
func (a *App) tunConfig() tun.Config {
	if a.core != nil && a.core.Client != nil {
		// 降级启动（开机时网络未就绪）会让启动期的 IPv6 解析得到空值；这里在
		// 读取前补一次有界解析，否则 TUN 脚本不会安装 IPv6 默认路由，
		// IPv6 流量会绕过隧道。已有值时该方法直接返回，不做 DNS 查询。
		//
		// 它同时可能触发一次新的 DNS 探测（resolveServerIPV6 会记录可达的内置/
		// 系统解析器），因此必须在 tunDNS 之前执行：在"此前所有标记尝试都失败、
		// 恰好这次刷新才成功"的边角情形下，先取 DNS 会让 TUN 拿到默认值而不是
		// 刚学到的可达服务器。
		a.core.Client.RefreshServerIPV6()
	}

	cfg := tun.Config{
		Socks5Addr: util.Socks5URI(a.cfg.Local.SocksPort),
		DNSServer:  tunDNS(),
	}
	if a.core != nil && a.core.Client != nil {
		if ipv6 := a.core.Client.Router().ServerIPV6(); ipv6 != "" {
			cfg.ServerIPV6 = ipv6
		}
	}
	return cfg
}

// methodFromServer 返回配置的 AEAD 加密方法；当配置指定了未知方法时
// 回退到 AES-256-GCM。
func (a *App) methodFromServer() protocol.Method {
	method := protocol.MethodFromString(a.cfg.DefaultServer().Method)
	if method == 0 {
		method = protocol.MethodAES256GCM
	}
	return method
}

// tunDNS 返回 TUN 模式下需要设置到系统的 DNS 服务器：本会话实测可达的解析器
// （查询作为原始 UDP 通过 TUN 设备发出，由客户端截获后按域名直连/代理拆分）。
// 取值顺序为内置直连 DNS → 系统 DNS（DHCP/内网解析器）→ 内置池第一个 IPv4 项，
// 见 dns.PreferredSystemDNS。
//
// 它与 enable_forward_dns 无关：转发服务器是给 LAN 设备当解析器用的（监听
// 0.0.0.0:53，见 runner.forwardDNSListenAddr），把本机 TUN 的解析器也指向它
// 只会让本机解析绕一圈并丢掉按域名拆分的路径。
func tunDNS() string {
	return easydns.PreferredSystemDNS()
}

func exampleV3Config() string {
	cfg := config.ClientConfig{
		ConfigVersion: 3,
		Servers: []*config.ServerProfile{{
			Address:  "your-domain.com",
			Port:     sharedconfig.DefaultServerPort,
			Password: "your-password",
			Method:   sharedconfig.DefaultMethod,
			SNI:      "",
			CAPath:   "",
			Default:  true,
		}},
		Local: config.LocalConfig{
			SocksPort:        sharedconfig.DefaultSocksPort,
			HTTPPort:         sharedconfig.DefaultHTTPPort,
			BindAll:          false,
			DisableSysProxy:  false,
			EnableForwardDNS: false,
			EnableTun2socks:  false,
			EnableQUIC:       false,
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
			ConnLifetimeSec:   sharedconfig.DefaultConnLifetimeSec,
			ConnMaxBytes:      sharedconfig.DefaultConnMaxBytes,
			DisableWarmUp:     false,
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
		DisableWarmUp: false,
		OutboundProto: "native",
		DirectFile:    "",
		ProxyFile:     "",
		LogLevel:      sharedconfig.DefaultLogLevel,
		LogFilePath:   "easyss.log",
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}
