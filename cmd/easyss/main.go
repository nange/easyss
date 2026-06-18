package main

import (
	"context"
	cryptorand "crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
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
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/version"
)

func main() {
	var printVer, showConfigExample, showConfigExampleSimple, daemon, disableTray, enableTun2socks bool
	var configFile, cmdIPV6Rule string

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file (full mode)")
	flag.BoolVar(&showConfigExampleSimple, "show-config-example-simple", false, "show a example of config file (simple mode)")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.BoolVar(&daemon, "daemon", runtime.GOOS != "windows", "run app as daemon")
	flag.BoolVar(&disableTray, "disable-tray", false, "disable system tray (windows/mac only)")
	flag.BoolVar(&enableTun2socks, "enable-tun2socks", false, "enable tun2socks model")
	flag.StringVar(&cmdIPV6Rule, "ipv6-rule", "", "set the ipv6 rule(auto, enable, disable), default: auto")

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

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Error("[EASYSS-V3] load config", "err", err)
		os.Exit(1)
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

func runDaemon() {
	exe, _ := os.Executable()
	attrs := &os.ProcAttr{}
	proc, err := os.StartProcess(exe, os.Args[1:], attrs)
	if err != nil {
		log.Error("[EASYSS-V3] daemon start", "err", err)
		os.Exit(1)
	}
	log.Info("[EASYSS-V3] daemon started", "pid", proc.Pid)
	os.Exit(0)
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
			BudgetRatio: a.cfg.Shaper.Cover.BudgetRatio,
		},
	}

	timeout := a.cfg.TimeoutDuration()
	streamIdleTimeout := time.Duration(sharedconfig.DefaultTCPStreamIdleTimeout) * time.Second
	if 4*timeout > streamIdleTimeout {
		streamIdleTimeout = 4 * timeout
	}
	a.streamHandler = proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, streamIdleTimeout)

	if a.cfg.Local.SocksPort > 0 {
		socksAddr := "127.0.0.1:" + strconv.Itoa(a.cfg.Local.SocksPort)
		if a.cfg.Local.BindAll {
			socksAddr = "[::]:" + strconv.Itoa(a.cfg.Local.SocksPort)
		}
		socksServer, err := proxy.NewSocks5Server(socksAddr, a.cfg.AuthUsername, a.cfg.AuthPassword, a.streamHandler, cli.Router(), method, !a.cfg.Local.EnableQUIC, timeout, cli.DialContext)
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
	go a.pingBackground()
	go a.statsLoop()

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
}

func (a *App) PingLatencyCh() <-chan time.Duration {
	return a.pingLatCh
}

func (a *App) pingBackground() {
	pingOnce := func() {
		if a.cli == nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		lat, err := a.cli.Ping(ctx)
		if err != nil {
			log.Debug("[EASYSS-V3] ping failed", "err", err)
			select {
			case a.pingLatCh <- -1:
			default:
			}
			return
		}

		log.Info("[EASYSS-V3] ping latency", "latency", lat)

		select {
		case a.pingLatCh <- lat:
		default:
		}
	}

	pingOnce()

	for {
		sleepDuration := randomPingInterval()
		timer := time.NewTimer(sleepDuration)
		select {
		case <-timer.C:
			pingOnce()
		case <-a.pingCloser:
			timer.Stop()
			return
		}
	}
}

func randomPingInterval() time.Duration {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(21))
	if err != nil {
		return 15 * time.Second
	}
	return time.Duration(10+int(n.Int64())) * time.Second
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
				"proxy_tx", stats.HumanBytes(snap.ProxyBytesSent),
				"proxy_rx", stats.HumanBytes(snap.ProxyBytesRecv),
				"tcp_conns", snap.TCPConnections,
				"udp_assoc", snap.UDPAssociations,
				"dns(hit)", snap.DNSCacheHits,
				"dns(miss)", snap.DNSCacheMisses,
				"dns(proxy)", snap.DNSProxyQueries,
				"dns(direct)", snap.DNSDirectQueries,
				"padding", stats.HumanBytes(snap.PaddingBytes),
				"records", snap.RecordsWritten,
			)
		case <-a.statsCloser:
			return
		}
	}
}

func exampleV3Config() string {
	return `{
  "version": 3,
  "servers": [{
    "address": "your-domain.com",
    "port": 443,
    "password": "your-password",
    "method": "aes-256-gcm",
    "sn": "",
    "ca_path": "",
    "default": true
  }],
  "local": {
    "socks_port": 2080,
    "http_port": 3080,
    "bind_all": false,
    "disable_sys_proxy": false,
    "enable_forward_dns": false,
    "enable_tun2socks": false,
    "enable_quic": false,
    "tun_config": {}
  },
  "routing": {
    "proxy_rule": "auto",
    "ipv6_rule": "auto",
    "direct_ips_file": "",
    "direct_domains_file": ""
  },
  "transport": {
    "protocol": "h2",
    "endpoint_prefix": "/v3",
    "conn_count_min": 8,
    "conn_count_max": 16
  },
  "shaper": {
    "batch_window_ms": 3,
    "cover": {
      "budget_ratio": 0
    }
  },
  "log": {
    "level": "info",
    "file_path": ""
  },
  "timeout": 30,
	  "auth_username": "",
	  "auth_password": ""
}`
}

func exampleSimpleConfig() string {
	return `{
  "server": "your-domain.com",
  "server_port": 443,
  "password": "your-password",
  "local_port": 2080,
  "method": "aes-256-gcm",
  "timeout": 30,
  "bind_all": false,
  "outbound_proto": "native",
  "log_level": "info",
  "log_file_path": ""
}`
}
