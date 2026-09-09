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
	"strconv"
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
		switch cmdOutboundProto {
		case "native", "h2":
			cfg.Transport.Protocol = "h2"
		default:
			log.Error("[EASYSS-V3] invalid outbound-proto", "value", cmdOutboundProto)
			os.Exit(1)
		}
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

	statsCloser chan struct{}
	statsOnce   sync.Once
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
		// creation here to avoid "operation not permitted".
		if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && !IsRoot() {
			log.Warn("[EASYSS-V3] tun2socks requires root; skipped (use sudo, or run with system tray for automatic elevation)")
		} else {
			// runner.Run already ensured the server hostname resolves and
			// pre-populated the DNS cache (resolveServerDomain), so TUN-mode
			// DNS can never deadlock on the server domain.
			socksProxyAddr := "socks5://127.0.0.1:" + strconv.Itoa(a.cfg.Local.SocksPort)
			tunCfg := tun.Config{
				Socks5Addr: socksProxyAddr,
				DNSServer:  tunDNS(a.cfg),
			}
			if ipv6 := a.core.Client.Router().ServerIPV6(); ipv6 != "" {
				tunCfg.ServerIPV6 = ipv6
			}
			a.tunMgr = tun.New(tunCfg)

			method := protocol.MethodFromString(a.cfg.DefaultServer().Method)
			if method == 0 {
				method = protocol.MethodAES256GCM
			}
			icmpHandler := tun.NewICMPHandler(a.core.Client.Router())
			icmpHandler.SetProxy(a.core.StreamHandler, method)
			a.tunMgr.SetICMPHandler(icmpHandler)

			go func() {
				if err := a.tunMgr.Start(); err != nil {
					log.Error("[EASYSS-V3] tun2socks", "err", err)
				}
			}()
		}
	}

	a.statsCloser = make(chan struct{})
	go a.statsLoop()

	if a.cfg.PprofEnabled {
		a.pprofSrv = pprof.StartPprof()
	}

	return nil
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
	a.statsOnce.Do(func() {
		close(a.statsCloser)
	})

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

func (a *App) statsLoop() {
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
		case <-a.statsCloser:
			return
		}
	}
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
