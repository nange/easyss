package runner

import (
	"strconv"

	"github.com/nange/easyss/v3/client"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
)

type Core struct {
	Cfg           *config.ClientConfig
	Client        *client.Client
	SocksServer   *proxy.Socks5Server
	HTTPServer    *proxy.HTTPProxyServer
	StreamHandler *proxy.StreamHandler
	DNSServer     *dns.ForwardServer
}

func New(cfg *config.ClientConfig) (*Core, error) {
	cli, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	method := protocol.MethodFromString(cfg.DefaultServer().Method)
	if method == 0 {
		method = protocol.MethodAES256GCM
	}

	shaperCfg := shaper.Config{
		BatchWindowMS: cfg.Shaper.BatchWindowMS,
		Cover: shaper.CoverConfig{
			BudgetRatio: cfg.Shaper.CoverBudgetRatio,
			BudgetCap:   cfg.Shaper.CoverBudgetCap,
		},
	}

	timeout := cfg.TimeoutDuration()
	streamIdleTimeout := 10 * timeout
	udpIdleTimeout := 2 * timeout

	streamHandler := proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, streamIdleTimeout)
	streamHandler.OnRTT = cli.LatencyTracker().Record

	c := &Core{
		Cfg:           cfg,
		Client:        cli,
		StreamHandler: streamHandler,
	}

	if cfg.Local.SocksPort > 0 {
		socksAddr := "127.0.0.1:" + strconv.Itoa(cfg.Local.SocksPort)
		if cfg.Local.BindAll {
			socksAddr = "[::]:" + strconv.Itoa(cfg.Local.SocksPort)
		}
		socksServer, err := proxy.NewSocks5Server(socksAddr, cfg.AuthUsername, cfg.AuthPassword,
			streamHandler, cli.Router(), method, !cfg.Local.EnableQUIC, udpIdleTimeout, cli.DialContext)
		if err != nil {
			_ = cli.Close()
			return nil, err
		}
		c.SocksServer = socksServer
		log.Info("[EASYSS] starting socks5 server", "addr", socksAddr)
		go func() {
			if err := c.SocksServer.Start(); err != nil {
				log.Error("[EASYSS] socks5 server", "err", err)
			}
		}()
	}

	if cfg.Local.HTTPPort > 0 {
		if cfg.Local.SocksPort <= 0 {
			_ = cli.Close()
			return nil, errSocksRequired
		}
		httpAddr := "127.0.0.1:" + strconv.Itoa(cfg.Local.HTTPPort)
		if cfg.Local.BindAll {
			httpAddr = "[::]:" + strconv.Itoa(cfg.Local.HTTPPort)
		}
		socksAddr := "127.0.0.1:" + strconv.Itoa(cfg.Local.SocksPort)
		httpServer, err := proxy.NewHTTPProxyServer(httpAddr, socksAddr, cfg.AuthUsername, cfg.AuthPassword,
			timeout, streamHandler, cli.Router(), method, cli.DialContext)
		if err != nil {
			c.cleanup()
			return nil, err
		}
		c.HTTPServer = httpServer
		log.Info("[EASYSS] starting http proxy server", "addr", httpAddr)
		go func() {
			if err := c.HTTPServer.Start(); err != nil {
				log.Error("[EASYSS] http proxy server", "err", err)
			}
		}()
	}

	if cfg.Local.EnableForwardDNS {
		dnsAddr := "127.0.0.1:53"
		c.DNSServer = dns.NewForwardServer(dnsAddr, cli.Router().ShouldIPV6Disable())
		log.Info("[EASYSS] starting dns forward server", "addr", dnsAddr)
		go func() {
			if err := c.DNSServer.Start(); err != nil {
				log.Error("[EASYSS] dns forward server", "err", err)
			}
		}()
	}

	log.Info("[EASYSS] started successfully")
	return c, nil
}

func (c *Core) Stop() {
	c.cleanup()
	log.Info("[EASYSS] stopped")
}

func (c *Core) cleanup() {
	if c.SocksServer != nil {
		_ = c.SocksServer.Close()
	}
	if c.HTTPServer != nil {
		_ = c.HTTPServer.Close()
	}
	if c.DNSServer != nil {
		_ = c.DNSServer.Shutdown()
	}
	if c.Client != nil {
		_ = c.Client.Close()
	}
}
