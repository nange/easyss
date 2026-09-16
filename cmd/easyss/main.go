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
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/nange/easyss/v3/client/config"
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
	// The "selfupdate" and "tun-helper" subcommands are handled before flag
	// parsing so they never collide with the proxy flags. selfupdate replaces
	// the running binary and exits; tun-helper runs this binary as the
	// elevated TUN helper (spawned internally by the tray process) and exits.
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

	// Custom usage so --help/-h also introduces the "selfupdate" and
	// "tun-helper" subcommands, which are handled before flag parsing and
	// would otherwise be invisible.
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

	// On macOS the app is often launched by Finder/launchd with cwd=/,
	// so a relative config path is first looked up in the cwd and then
	// falls back to the executable directory.
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

	// Resolve relative file paths (direct_file/proxy_file/ca_path) against
	// the executable directory so that macOS Finder/launchd launches (cwd=/)
	// can still find the files placed next to the binary/.app bundle.
	cfg.ResolveFilePaths()

	if cfg.Log.FilePath != "" && !filepath.IsAbs(cfg.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			cfg.Log.FilePath = filepath.Join(dir, cfg.Log.FilePath)
		}
	}

	log.Info("[EASYSS-V3] set log-level", "level", cfg.Log.Level)
	log.Init(cfg.Log.FilePath, cfg.Log.Level)
	log.Info("[EASYSS-V3] " + version.String())

	// Remove leftovers from a previous self-update (the renamed old binary
	// kept for Windows/macOS, stale staging directories). Runs after
	// log.Init so its logs land in the configured output instead of the
	// default stdout handler, which is invisible in GUI builds.
	selfupdate.CleanupOld()

	// Make config file path absolute so that any elevated helper
	// process can find it regardless of working directory.
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
	configFile string // absolute path to config file
	core       *runner.Core
	tunMgr     *tun.Manager
	pprofSrv   *http.Server

	// startupWarn records the first non-fatal startup warning (e.g. the
	// server domain failed to resolve, or a custom rule file failed to
	// load). The client keeps running; the tray surfaces it as a system
	// notification, headless builds log it.
	startupWarn error

	// statsCloser stops the background stats logger. It is guarded by
	// statsMu because Start/Stop can run concurrently (tray menu handlers)
	// and because a failed Start leaves it unset: closing a nil channel
	// would panic.
	statsMu     sync.Mutex
	statsCloser chan struct{}
}

func (a *App) Start() error {
	core, err := runner.Run(a.cfg)
	if err != nil {
		return err
	}
	a.core = core
	a.setStartupWarn(core.StartupWarn)

	if a.cfg.Local.EnableTun2socks {
		// On macOS and Linux non-root, TUN is started via privilege
		// elevation (helper process or restart as root). Skip direct
		// creation here to avoid "operation not permitted". Reaching this
		// branch means the user asked for system-wide traffic but will not
		// get it, so the tray tells them why instead of leaving them with a
		// silently unproxied system. main.go is shared with headless builds,
		// so this goes through tunStartNotify rather than the tray directly.
		if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && !IsRoot() {
			log.Warn("[EASYSS-V3] tun2socks requires root; skipped (use sudo, or run with system tray for automatic elevation)")
			notifyTunSkippedNoRoot()
		} else {
			// runner.Run already ensured the server hostname resolves and
			// pre-populated the DNS cache (resolveServerDomain), so TUN-mode
			// DNS can never deadlock on the server domain.
			a.tunMgr = tun.New(a.tunConfig())

			icmpHandler := tun.NewICMPHandler(a.core.Client.Router())
			icmpHandler.SetProxy(a.core.StreamHandler, a.methodFromServer())
			a.tunMgr.SetICMPHandler(icmpHandler)

			startTunEngine(a.tunMgr, "device")
		}
	}

	a.startStatsLoop()

	if a.cfg.PprofEnabled {
		a.pprofSrv = pprof.StartPprof()
	}

	return nil
}

// tunStartFailureHook, when non-nil, runs after the TUN engine fails to start.
// The tray build installs it in buildTray so that a failure at startup also
// reverts the menu item (see (*TrayApp).revertTunStart). Headless and
// --disable-tray builds leave it nil: they have no UI state to revert, and the
// engine is released by Stop(). It is only called by trayStartTunFailure, which
// additionally reports the reason to the user.
var tunStartFailureHook func()

// tunStartNotify, when non-nil, reports a TUN start failure to the user through
// the tray's system notification. The tray build installs it in buildTray (see
// (*TrayApp).notifyTunStartFailure); headless and --disable-tray builds leave
// it nil, so the reason reaches the log file alone. Without it the failure
// would be invisible: the proxy core keeps running, and only the state the user
// just turned on (system-wide traffic) is missing.
var tunStartNotify func(msg string)

// tunStartErrorText, when non-nil, turns a TUN start error into the message
// shown to the user, and may return an empty string for a failure the user
// caused deliberately (see friendlyTunError in tray.go, installed in
// buildTray). It stays nil in headless and --disable-tray builds, where
// trayStartTunFailure falls back to err.Error() — main.go is compiled into
// every build and cannot reference tray.go.
//
// The current value is read on the engine goroutine, so it is written exactly
// once, during startup, before any engine start can fail.
var tunStartErrorText func(err error) string

// startTunEngine starts the tun2socks engine in the background. Manager.Start
// blocks through the device setup, the settle delay and the platform route
// scripts (up to 60s), so it must not run on the caller's goroutine.
//
// mode names how the device was acquired ("device" by name, "fd" from the
// elevated helper) so a failure is traceable to one of the two paths.
//
// Upstream reports a failed start as an error instead of the log.Fatalf that
// used to kill the process (tun2socks #550/#552), so the half-enabled state
// has to be undone by whoever owns it rather than by exiting.
func startTunEngine(mgr *tun.Manager, mode string) {
	go func() {
		if err := mgr.Start(); err != nil {
			log.Error("[EASYSS-V3] tun2socks start", "mode", mode, "err", err)
			trayStartTunFailure(err)
		}
	}()
}

// trayStartTunFailure is the single owner of "the TUN engine failed to start":
// it reverts the half-enabled state (hook) and tells the user why (notify).
//
// tunStartErrorText may return an empty message for a failure the user asked for
// rather than suffered (see friendlyTunError): Stop() cancelling the start —
// toggle off, server switch, app exit — is not an error worth interrupting
// anyone over. The revert still runs in that case: the menu has to end up
// unchecked regardless of who stopped what.
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

// notifyTunSkippedNoRoot reports that TUN was configured but could not be
// started without administrator privileges. The text is fixed: there is no
// underlying error to append, and the actionable hint is the same on every
// platform that reaches this path.
func notifyTunSkippedNoRoot() {
	if tunStartNotify != nil {
		tunStartNotify("Tun2socks 未启用：需要管理员权限，请以 root 运行或使用系统托盘授权")
	}
}

// setStartupWarn records the first non-fatal startup warning. The client
// keeps running; the tray surfaces it as a system notification, headless
// builds log it.
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

// startStatsLoop (re)starts the background stats logger, stopping a previous
// loop if one is still running. The stop channel is captured by the goroutine
// so a later restart cannot leave the old loop selecting on the new channel.
func (a *App) startStatsLoop() {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	if a.statsCloser != nil {
		close(a.statsCloser)
	}
	a.statsCloser = make(chan struct{})
	go a.statsLoop(a.statsCloser)
}

// stopStatsLoop stops the background stats logger. It is safe to call on an
// App that never started one, and safe to call repeatedly.
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

// tunConfig builds the TUN configuration for this App. It is the single
// construction point shared by the startup path and the tray toggle, so the
// two cannot drift apart (notably the server-IPv6 hint, which the tray path
// used to omit).
func (a *App) tunConfig() tun.Config {
	cfg := tun.Config{
		Socks5Addr: util.Socks5URI(a.cfg.Local.SocksPort),
		DNSServer:  tunDNS(a.cfg),
	}
	if a.core != nil && a.core.Client != nil {
		if ipv6 := a.core.Client.Router().ServerIPV6(); ipv6 != "" {
			cfg.ServerIPV6 = ipv6
		}
	}
	return cfg
}

// methodFromServer returns the configured AEAD method, falling back to
// AES-256-GCM when the config names an unknown one.
func (a *App) methodFromServer() protocol.Method {
	method := protocol.MethodFromString(a.cfg.DefaultServer().Method)
	if method == 0 {
		method = protocol.MethodAES256GCM
	}
	return method
}

// tunDNS returns the DNS server to set on the system during TUN mode.
// When the built-in DNS forward server is enabled, queries should go to
// 127.0.0.1 so they are handled and logged by EasySS. Otherwise a public
// DNS server is used and queries go through the TUN device as raw UDP.
func tunDNS(cfg *config.ClientConfig) string {
	if cfg.Local.EnableForwardDNS {
		return "127.0.0.1"
	}
	return config.DefaultSystemDNS
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
