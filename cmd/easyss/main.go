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
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/version"
)

func main() {
	var printVer, showConfigExample, showConfigExampleSimple, daemon, disableTray, enableTun2socks, tunHelper bool
	var configFile, cmdOutboundProto string
	var pprofEnabled bool

	// TUN helper flags (used when --tun-helper is set).
	var thSocketPath, thDevice, thTunIP, thTunGW, thLocalGateway string
	var thTunIPV6Sub, thTunGWV6, thServerIPV6, thLocalGatewayV6, thDNSServer string

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
	flag.BoolVar(&sc.EnableQUIC, "enable-quic", false, "enable QUIC protocol")
	flag.StringVar(&sc.SN, "sn", "", "TLS SNI override")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.BoolVar(&daemon, "daemon", runtime.GOOS != "windows", "run app as daemon")
	flag.BoolVar(&disableTray, "disable-tray", false, "disable system tray (windows/mac only)")
	flag.BoolVar(&enableTun2socks, "enable-tun2socks", false, "enable tun2socks model")
	flag.BoolVar(&tunHelper, "tun-helper", false, "run TUN helper (macOS privilege separation, internal)")
	flag.StringVar(&thSocketPath, "tun-helper-socket", "", "Unix socket path for fd passing")
	flag.StringVar(&thDevice, "tun-helper-device", "", "TUN device name")
	flag.StringVar(&thTunIP, "tun-helper-tun-ip", "", "TUN IP address")
	flag.StringVar(&thTunGW, "tun-helper-tun-gw", "", "TUN gateway")
	flag.StringVar(&thLocalGateway, "tun-helper-local-gateway", "", "Local gateway")
	flag.StringVar(&thTunIPV6Sub, "tun-helper-tun-ip-v6", "", "TUN IPv6 subnet")
	flag.StringVar(&thTunGWV6, "tun-helper-tun-gw-v6", "", "TUN IPv6 gateway")
	flag.StringVar(&thServerIPV6, "tun-helper-server-ip-v6", "", "Server IPv6 address")
	flag.StringVar(&thLocalGatewayV6, "tun-helper-local-gateway-v6", "", "Local IPv6 gateway")
	flag.StringVar(&thDNSServer, "tun-helper-dns", "", "DNS server to set during TUN mode")
	flag.StringVar(&sc.IPV6Rule, "ipv6-rule", "", "set the ipv6 rule(auto, enable, disable), default: auto")
	flag.StringVar(&sc.DirectFile, "direct-file", "", "custom direct file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
	flag.StringVar(&sc.ProxyFile, "proxy-file", "", "custom proxy file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
	flag.BoolVar(&pprofEnabled, "pprof", false, "enable pprof debug server on :6060")

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

	// TUN helper is a short-lived elevated process that opens the TUN device,
	// sets up routing/DNS, and passes the fd back to the parent. It does not
	// need any config — exit immediately after its work is done.
	if tunHelper {
		os.Exit(runTunHelper(thSocketPath, thDevice, thTunIP, thTunGW, thLocalGateway,
			thTunIPV6Sub, thTunGWV6, thServerIPV6, thLocalGatewayV6, thDNSServer))
	}

	if !filepath.IsAbs(configFile) {
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			if dir := util.CurrentDir(); dir != "" {
				altPath := filepath.Join(dir, configFile)
				if _, err := os.Stat(altPath); err == nil {
					configFile = altPath
				}
			}
		}
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		if sc.Server != "" && sc.Password != "" {
			cfg, err = config.BuildSimpleConfig(sc)
			if err != nil {
				log.Error("[EASYSS-V3] build config from args", "err", err)
				os.Exit(1)
			}
		} else {
			log.Error("[EASYSS-V3] load config", "err", err)
			os.Exit(1)
		}
	} else {
		config.ApplySimpleOverrides(cfg, sc)
	}

	if cfg.Log.FilePath != "" && !filepath.IsAbs(cfg.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			cfg.Log.FilePath = filepath.Join(dir, cfg.Log.FilePath)
		}
	}

	log.Info("[EASYSS-V3] set log-level", "level", cfg.Log.Level)
	log.Init(cfg.Log.FilePath, cfg.Log.Level)
	log.Info("[EASYSS-V3] " + version.String())

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
		"server", cfg.DefaultServerAddr(),
		"socks_port", cfg.Local.SocksPort,
		"http_port", cfg.Local.HTTPPort,
		"proxy_rule", cfg.Routing.ProxyRule,
		"ipv6_rule", cfg.Routing.IPV6Rule,
		"timeout", cfg.Timeout,
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

	statsCloser chan struct{}
	statsOnce   sync.Once
}

func (a *App) Start() error {
	core, err := runner.Run(a.cfg)
	if err != nil {
		return err
	}
	a.core = core

	if a.cfg.Local.EnableTun2socks {
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

		go func() {
			if err := a.tunMgr.Start(icmpHandler); err != nil {
				log.Error("[EASYSS-V3] tun2socks", "err", err)
			}
		}()
	}

	a.statsCloser = make(chan struct{})
	go a.statsLoop()
	stats.StartSpeedMonitor()

	if a.cfg.PprofEnabled {
		a.pprofSrv = pprof.StartPprof()
	}

	return nil
}

func (a *App) Stop() {
	a.statsOnce.Do(func() {
		close(a.statsCloser)
	})
	stats.StopSpeedMonitor()

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
			Port:     443,
			Password: "your-password",
			Method:   "aes-256-gcm",
			SNI:      "",
			CAPath:   "",
			Default:  true,
		}},
		Local: config.LocalConfig{
			SocksPort:        2080,
			HTTPPort:         3080,
			BindAll:          false,
			DisableSysProxy:  false,
			EnableForwardDNS: false,
			EnableTun2socks:  false,
			EnableQUIC:       false,
		},
		Routing: config.RoutingConfig{
			ProxyRule:  "auto",
			IPV6Rule:   "auto",
			DirectFile: "",
			ProxyFile:  "",
		},
		Transport: config.TransportConfig{
			Protocol:          "h2",
			ConnCountMax:      12,
			StreamThreshold:   8,
			PrioritySlotRatio: 0.5,
		},
		Shaper: config.ShaperConfig{
			BatchWindowMS:    3,
			CoverBudgetRatio: 0.03,
			CoverBudgetCap:   128 * 1024,
		},
		Log: config.LogConfig{
			Level:    "info",
			FilePath: "easyss.log",
		},
		Timeout:      30,
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
		ServerPort:    443,
		Password:      "your-password",
		Method:        "aes-256-gcm",
		LocalPort:     2080,
		ProxyRule:     "auto",
		Timeout:       30,
		BindAll:       false,
		OutboundProto: "native",
		DirectFile:    "",
		ProxyFile:     "",
		LogLevel:      "info",
		LogFilePath:   "easyss.log",
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}
