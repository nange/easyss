package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	_ "time/tzdata"

	"github.com/nange/easyss/v3/client"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/version"
)

func main() {
	var printVer, showConfigExample, daemon, disableTray, enableTun2socks bool
	var configFile string

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.BoolVar(&daemon, "daemon", runtime.GOOS != "windows", "run app as daemon")
	flag.BoolVar(&disableTray, "disable-tray", false, "disable system tray (windows/mac only)")
	flag.BoolVar(&enableTun2socks, "enable-tun2socks", false, "enable tun2socks model")

	flag.Parse()

	if printVer {
		version.Print()
		os.Exit(0)
	}
	if showConfigExample {
		fmt.Println(exampleV3Config())
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
		Mode:          a.cfg.Shaper.Mode,
		BatchWindowMS: a.cfg.Shaper.BatchWindowMS,
	}

	timeout := a.cfg.TimeoutDuration()
	a.streamHandler = proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, timeout/2)

	if a.cfg.Local.SocksPort > 0 {
		socksAddr := "127.0.0.1:" + strconv.Itoa(a.cfg.Local.SocksPort)
		if a.cfg.Local.BindAll {
			socksAddr = "0.0.0.0:" + strconv.Itoa(a.cfg.Local.SocksPort)
		}
		a.socksServer = proxy.NewSocks5Server(socksAddr, a.cfg.AuthUsername, a.cfg.AuthPassword, a.streamHandler, cli.Router(), method, !a.cfg.Local.EnableQUIC, timeout)
		go func() {
			if err := a.socksServer.Start(); err != nil {
				log.Error("[EASYSS-V3] socks5 server", "err", err)
			}
		}()
	}

	if a.cfg.Local.HTTPPort > 0 {
		httpAddr := "127.0.0.1:" + strconv.Itoa(a.cfg.Local.HTTPPort)
		if a.cfg.Local.BindAll {
			httpAddr = "0.0.0.0:" + strconv.Itoa(a.cfg.Local.HTTPPort)
		}
		a.httpServer = proxy.NewHTTPProxyServer(httpAddr, a.streamHandler, cli.Router(), method)
		go func() {
			if err := a.httpServer.Start(); err != nil {
				log.Error("[EASYSS-V3] http proxy server", "err", err)
			}
		}()
	}

	if a.cfg.Local.EnableForwardDNS {
		dnsAddr := "127.0.0.1:53"
		forwardServer := dns.NewForwardServer(dnsAddr)
		go func() {
			if err := forwardServer.Start(); err != nil {
				log.Error("[EASYSS-V3] dns forward server", "err", err)
			}
		}()
	}

	if a.cfg.Local.EnableTun2socks {
		socksProxyAddr := "socks5://127.0.0.1:" + strconv.Itoa(a.cfg.Local.SocksPort)
		a.tunMgr = tun.New(tun.Config{
			Socks5Addr: socksProxyAddr,
			LogLevel:   a.cfg.Log.Level,
		})

		icmpHandler := tun.NewICMPHandler(cli.Router())
		icmpHandler.SetProxy(a.streamHandler, method)

		go func() {
			if err := a.tunMgr.Start(icmpHandler); err != nil {
				log.Error("[EASYSS-V3] tun2socks", "err", err)
			}
		}()
	}

	return nil
}

func (a *App) Stop() {
	if a.tunMgr != nil {
		a.tunMgr.Stop()
	}
	if a.socksServer != nil {
		_ = a.socksServer.Close()
	}
	if a.httpServer != nil {
		_ = a.httpServer.Close()
	}
	if a.cli != nil {
		_ = a.cli.Close()
	}
}

func exampleV3Config() string {
	return `{
  "config_version": 3,
  "servers": [{
    "name": "default",
    "address": "your-domain.com",
    "port": 443,
    "password": "your-password",
    "method": "aes-256-gcm",
    "default": true
  }],
  "local": {
    "socks_port": 2080,
    "http_port": 3080
  },
  "routing": {
    "proxy_rule": "auto"
  },
  "transport": {
    "conn_count_min": 8,
    "conn_count_max": 16
  },
  "shaper": {
    "mode": "light",
    "batch_window_ms": 5
  },
  "log": {
    "level": "info"
  },
  "timeout": 30
}`
}
