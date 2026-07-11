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

	"github.com/nange/easyss/v3/client"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/pprof"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/version"
)

func main() {
	var printVer, showConfigExample, showConfigExampleSimple, daemon, disableTray, enableTun2socks, enableQUIC bool
	var configFile, cmdIPV6Rule string
	var cmdServer, cmdPassword, cmdMethod, cmdProxyRule, cmdOutboundProto, cmdLogLevel, cmdSN, cmdDirectFile, cmdProxyFile string
	var cmdServerPort, cmdLocalPort, cmdTimeout int
	var pprofEnabled bool

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file (full mode)")
	flag.BoolVar(&showConfigExampleSimple, "show-config-example-simple", false, "show a example of config file (simple mode)")
	flag.StringVar(&cmdServer, "s", "", "server address")
	flag.IntVar(&cmdServerPort, "p", 0, "server port")
	flag.StringVar(&cmdPassword, "k", "", "password")
	flag.StringVar(&cmdMethod, "m", "", "encryption method (aes-256-gcm, chacha20-poly1305)")
	flag.StringVar(&cmdProxyRule, "proxy-rule", "", "proxy rule (auto, reverse_auto, proxy, direct, auto_block)")
	flag.StringVar(&cmdOutboundProto, "outbound-proto", "", "outbound protocol (native, h2)")
	flag.IntVar(&cmdLocalPort, "l", 0, "local socks5 port")
	flag.IntVar(&cmdTimeout, "t", 0, "timeout in seconds")
	flag.StringVar(&cmdLogLevel, "log-level", "", "log level (debug, info, warn, error)")
	flag.BoolVar(&enableQUIC, "enable-quic", false, "enable QUIC protocol")
	flag.StringVar(&cmdSN, "sn", "", "TLS SNI override")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.BoolVar(&daemon, "daemon", runtime.GOOS != "windows", "run app as daemon")
	flag.BoolVar(&disableTray, "disable-tray", false, "disable system tray (windows/mac only)")
	flag.BoolVar(&enableTun2socks, "enable-tun2socks", false, "enable tun2socks model")
	flag.StringVar(&cmdIPV6Rule, "ipv6-rule", "", "set the ipv6 rule(auto, enable, disable), default: auto")
	flag.StringVar(&cmdDirectFile, "direct-file", "", "custom direct file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
	flag.StringVar(&cmdProxyFile, "proxy-file", "", "custom proxy file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
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

	// If config file path is relative and not found in CWD,
	// try the executable's directory (e.g. double-click on macOS).
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
		if cmdServer != "" && cmdPassword != "" {
			cfg = config.DefaultConfig()
			srv := &config.ServerProfile{
				Address:  cmdServer,
				Password: cmdPassword,
				Default:  true,
			}
			if cmdServerPort > 0 {
				srv.Port = cmdServerPort
			}
			if cmdMethod != "" {
				srv.Method = cmdMethod
			}
			if cmdSN != "" {
				srv.SNI = cmdSN
			}
			cfg.Servers = []*config.ServerProfile{srv}
			if srv.Port == 0 {
				srv.Port = 443
			}
			if srv.Method == "" {
				srv.Method = "aes-256-gcm"
			}
		} else {
			log.Error("[EASYSS-V3] load config", "err", err)
			os.Exit(1)
		}
	}

	// Resolve relative log file path to absolute based on executable directory,
	// so both log writing and "View Log" from systray point to the same file
	// regardless of the process's current working directory.
	if cfg.Log.FilePath != "" && !filepath.IsAbs(cfg.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			cfg.Log.FilePath = filepath.Join(dir, cfg.Log.FilePath)
		}
	}

	log.Info("[EASYSS-V3] set log-level", "level", cfg.Log.Level)
	log.Init(cfg.Log.FilePath, cfg.Log.Level)
	log.Info("[EASYSS-V3] " + version.String())

	if enableTun2socks {
		cfg.Local.EnableTun2socks = true
	}
	if cmdIPV6Rule != "" {
		cfg.Routing.IPV6Rule = cmdIPV6Rule
	}

	// CLI overrides for simplified mode fields
	srv := cfg.DefaultServer()
	if srv != nil {
		if cmdServer != "" {
			srv.Address = cmdServer
		}
		if cmdServerPort > 0 {
			srv.Port = cmdServerPort
		}
		if cmdPassword != "" {
			srv.Password = cmdPassword
		}
		if cmdMethod != "" {
			srv.Method = cmdMethod
		}
		if cmdSN != "" {
			srv.SNI = cmdSN
		}
	}
	if cmdProxyRule != "" {
		cfg.Routing.ProxyRule = cmdProxyRule
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
	if cmdLocalPort > 0 {
		cfg.Local.SocksPort = cmdLocalPort
		if cfg.Local.HTTPPort == 0 {
			cfg.Local.HTTPPort = cmdLocalPort + 1000
		}
	}
	if cmdTimeout > 0 {
		cfg.Timeout = cmdTimeout
	}
	if cmdLogLevel != "" {
		cfg.Log.Level = cmdLogLevel
	}
	if enableQUIC {
		cfg.Local.EnableQUIC = true
	}
	if cmdDirectFile != "" {
		cfg.Routing.DirectFile = cmdDirectFile
	}
	if cmdProxyFile != "" {
		cfg.Routing.ProxyFile = cmdProxyFile
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

	app := &App{cfg: cfg}
	runApp(disableTray, daemon, app)
}

func sigWait() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	log.Info("[EASYSS-V3] got signal to exit", "signal", <-c)
}

type App struct {
	cfg           *config.ClientConfig
	cli           *client.Client
	tunMgr        *tun.Manager
	socksServer   *proxy.Socks5Server
	httpServer    *proxy.HTTPProxyServer
	streamHandler *proxy.StreamHandler
	dnsServer     *dns.ForwardServer

	pingLatCh  chan time.Duration
	pingCloser chan struct{}
	pingOnce   sync.Once

	statsCloser chan struct{}
	statsOnce   sync.Once

	pprofSrv *http.Server
}

func (a *App) Start() error {
	cli, err := client.New(a.cfg)
	if err != nil {
		return err
	}
	a.cli = cli

	method := protocol.MethodFromString(a.cfg.DefaultServer().Method)
	if method == 0 {
		method = protocol.MethodAES256GCM
	}

	shaperCfg := shaper.Config{
		BatchWindowMS: a.cfg.Shaper.BatchWindowMS,
		Cover: shaper.CoverConfig{
			BudgetRatio: a.cfg.Shaper.CoverBudgetRatio,
			BudgetCap:   a.cfg.Shaper.CoverBudgetCap,
		},
	}

	timeout := a.cfg.TimeoutDuration()
	streamIdleTimeout := 10 * timeout
	udpIdleTimeout := 2 * timeout
	a.streamHandler = proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, streamIdleTimeout)
	a.streamHandler.OnRTT = cli.LatencyTracker().Record

	if a.cfg.Local.SocksPort > 0 {
		socksAddr := "127.0.0.1:" + strconv.Itoa(a.cfg.Local.SocksPort)
		if a.cfg.Local.BindAll {
			socksAddr = "[::]:" + strconv.Itoa(a.cfg.Local.SocksPort)
		}
		socksServer, err := proxy.NewSocks5Server(socksAddr, a.cfg.AuthUsername, a.cfg.AuthPassword, a.streamHandler, cli.Router(), method, !a.cfg.Local.EnableQUIC, udpIdleTimeout, cli.DialContext)
		if err != nil {
			log.Error("[EASYSS-V3] create socks5 server", "err", err)
			return err
		}
		a.socksServer = socksServer
		log.Info("[EASYSS-V3] starting socks5 server", "addr", socksAddr)
		go func() {
			if err := a.socksServer.Start(); err != nil {
				log.Error("[EASYSS-V3] socks5 server", "err", err)
			}
		}()
	}

	if a.cfg.Local.HTTPPort > 0 {
		if a.cfg.Local.SocksPort <= 0 {
			return fmt.Errorf("http proxy requires local.socks_port to be enabled")
		}
		httpAddr := "127.0.0.1:" + strconv.Itoa(a.cfg.Local.HTTPPort)
		if a.cfg.Local.BindAll {
			httpAddr = "[::]:" + strconv.Itoa(a.cfg.Local.HTTPPort)
		}
		socksAddr := "127.0.0.1:" + strconv.Itoa(a.cfg.Local.SocksPort)
		a.httpServer, err = proxy.NewHTTPProxyServer(httpAddr, socksAddr, a.cfg.AuthUsername, a.cfg.AuthPassword, timeout, a.streamHandler, cli.Router(), method, cli.DialContext)
		if err != nil {
			return err
		}
		log.Info("[EASYSS-V3] starting http proxy server", "addr", httpAddr)
		go func() {
			if err := a.httpServer.Start(); err != nil {
				log.Error("[EASYSS-V3] http proxy server", "err", err)
			}
		}()
	}

	if a.cfg.Local.EnableForwardDNS {
		dnsAddr := "127.0.0.1:53"
		a.dnsServer = dns.NewForwardServer(dnsAddr, cli.Router().ShouldIPV6Disable())
		go func() {
			if err := a.dnsServer.Start(); err != nil {
				log.Error("[EASYSS-V3] dns forward server", "err", err)
			}
		}()
	}

	if a.cfg.Local.EnableTun2socks {
		socksProxyAddr := "socks5://127.0.0.1:" + strconv.Itoa(a.cfg.Local.SocksPort)
		tunCfg := tun.Config{
			Socks5Addr: socksProxyAddr,
			DNSServer:  config.DefaultSystemDNS,
		}
		if ipv6 := cli.Router().ServerIPV6(); ipv6 != "" {
			tunCfg.ServerIPV6 = ipv6
		}
		a.tunMgr = tun.New(tunCfg)

		icmpHandler := tun.NewICMPHandler(cli.Router())
		icmpHandler.SetProxy(a.streamHandler, method)

		go func() {
			if err := a.tunMgr.Start(icmpHandler); err != nil {
				log.Error("[EASYSS-V3] tun2socks", "err", err)
			}
		}()
	}

	a.pingLatCh = make(chan time.Duration, 1)
	a.pingCloser = make(chan struct{})
	a.statsCloser = make(chan struct{})
	go a.latencyPoller()
	go a.statsLoop()

	if a.cfg.PprofEnabled {
		a.pprofSrv = pprof.StartPprof()
	}

	log.Info("[EASYSS-V3] started successfully")
	return nil
}

func (a *App) Stop() {
	a.pingOnce.Do(func() {
		close(a.pingCloser)
	})
	a.statsOnce.Do(func() {
		close(a.statsCloser)
	})

	if a.tunMgr != nil {
		a.tunMgr.Stop()
	}
	if a.socksServer != nil {
		if err := a.socksServer.Close(); err != nil {
			log.Debug("[EASYSS-V3] socks server close", "err", err)
		}
	}
	if a.httpServer != nil {
		if err := a.httpServer.Close(); err != nil {
			log.Debug("[EASYSS-V3] http server close", "err", err)
		}
	}
	if a.dnsServer != nil {
		if err := a.dnsServer.Shutdown(); err != nil {
			log.Debug("[EASYSS-V3] dns server shutdown", "err", err)
		}
	}
	if a.cli != nil {
		if err := a.cli.Close(); err != nil {
			log.Debug("[EASYSS-V3] client close", "err", err)
		}
	}
	if a.pprofSrv != nil {
		pprof.StopPprof(a.pprofSrv)
	}
}

func (a *App) PingLatencyCh() <-chan time.Duration {
	return a.pingLatCh
}

func (a *App) latencyPoller() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastReported time.Duration
	for {
		select {
		case <-ticker.C:
			if a.cli == nil {
				continue
			}
			est, ok := a.cli.LatencyTracker().Estimate()
			if !ok {
				continue
			}
			if est == lastReported {
				continue
			}
			lastReported = est
			select {
			case a.pingLatCh <- est:
			default:
			}
		case <-a.pingCloser:
			return
		}
	}
}

func (a *App) statsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if a.cli == nil {
				continue
			}
			snap := stats.Collect()
			trStats := a.cli.Transport().Stats()
			log.Info("[STATS]",
				"uptime", snap.Uptime().Round(time.Second),
				"conns", trStats.ConnCount,
				"active_streams", trStats.ActiveStream,
				"streams(opened)", snap.TotalStreamsOpened,
				"streams(closed)", snap.TotalStreamsClosed,
				"tx", stats.HumanBytes(snap.BytesSent),
				"rx", stats.HumanBytes(snap.BytesRecv),
				"raw_tx", stats.HumanBytes(snap.RawBytesSent),
				"raw_rx", stats.HumanBytes(snap.RawBytesRecv),
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
			Protocol:        "h2",
			EndpointPrefix:  "/v3",
			ConnCountMax:    6,
			StreamThreshold: 8,
		},
		Shaper: config.ShaperConfig{
			BatchWindowMS:    3,
			CoverBudgetRatio: 0.05,
			CoverBudgetCap:   128 * 1024,
		},
		Log: config.LogConfig{
			Level:    "info",
			FilePath: "easyss.log",
		},
		Timeout:         30,
		AuthUsername:    "",
		AuthPassword:    "",
		PprofEnabled:    false,
		LatencyOffsetMS: 50,
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

func exampleSimpleConfig() string {
	cfg := config.V2Config{
		Server:        "your-domain.com",
		ServerPort:    443,
		Password:      "your-password",
		Method:        "aes-256-gcm",
		LocalPort:     2080,
		ProxyRule:     "auto",
		Timeout:       30,
		BindALL:       false,
		OutboundProto: "native",
		DirectFile:    "",
		ProxyFile:     "",
		LogLevel:      "info",
		LogFilePath:   "easyss.log",
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}
