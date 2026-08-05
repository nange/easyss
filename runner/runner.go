package runner

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/nange/easyss/v3/client"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
)

var errSocksRequired = errors.New("http proxy requires socks_port to be enabled")

type Core struct {
	Cfg           *config.ClientConfig
	Client        *client.Client
	SocksServer   *proxy.Socks5Server
	HTTPServer    *proxy.HTTPProxyServer
	StreamHandler *proxy.StreamHandler
	DNSServer     *dns.ForwardServer
}

func Run(cfg *config.ClientConfig) (*Core, error) {
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
	dialTimeout := timeout / 2

	streamHandler := proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, streamIdleTimeout)

	c := &Core{
		Cfg:           cfg,
		Client:        cli,
		StreamHandler: streamHandler,
	}

	// Pre-bind all local listen addresses before starting any server
	// goroutine, so a listen failure (e.g. port already in use) aborts
	// startup with an error instead of being logged and silently ignored.
	var socksAddr, httpAddr, dnsAddr string
	if cfg.Local.SocksPort > 0 {
		socksAddr = "127.0.0.1:" + strconv.Itoa(cfg.Local.SocksPort)
		if cfg.Local.BindAll {
			socksAddr = "[::]:" + strconv.Itoa(cfg.Local.SocksPort)
		}
		if err := prebindTCP(socksAddr); err != nil {
			c.cleanup()
			return nil, fmt.Errorf("socks5 server listen %s: %w", socksAddr, err)
		}
	}
	if cfg.Local.HTTPPort > 0 {
		if cfg.Local.SocksPort <= 0 {
			_ = cli.Close()
			return nil, errSocksRequired
		}
		httpAddr = "127.0.0.1:" + strconv.Itoa(cfg.Local.HTTPPort)
		if cfg.Local.BindAll {
			httpAddr = "[::]:" + strconv.Itoa(cfg.Local.HTTPPort)
		}
		if err := prebindTCP(httpAddr); err != nil {
			c.cleanup()
			return nil, fmt.Errorf("http proxy server listen %s: %w", httpAddr, err)
		}
	}
	if cfg.Local.EnableForwardDNS {
		dnsAddr = "127.0.0.1:53"
		if err := prebindUDP(dnsAddr); err != nil {
			c.cleanup()
			return nil, fmt.Errorf("dns forward server listen %s: %w", dnsAddr, err)
		}
	}

	if socksAddr != "" {
		serverDomain := ""
		if svr := cfg.DefaultServer(); svr != nil && net.ParseIP(svr.Address) == nil {
			serverDomain = svr.Address
		}
		socksServer, err := proxy.NewSocks5Server(socksAddr, cfg.AuthUsername, cfg.AuthPassword,
			streamHandler, cli.Router(), serverDomain, method, !cfg.Local.EnableQUIC, dialTimeout, udpIdleTimeout, cli.DialContext)
		if err != nil {
			_ = cli.Close()
			return nil, err
		}
		c.SocksServer = socksServer
		log.Info("[EASYSS] starting socks5 server", "addr", socksAddr)
		c.SocksServer.MarkStarted()
		go func() {
			if err := c.SocksServer.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Error("[EASYSS] socks5 server", "err", err)
			}
		}()
	}

	if httpAddr != "" {
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
			if err := c.HTTPServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("[EASYSS] http proxy server", "err", err)
			}
		}()
	}

	if dnsAddr != "" {
		c.DNSServer = dns.NewForwardServer(dnsAddr, cli.Router().ShouldIPV6Disable())
		log.Info("[EASYSS] starting dns forward server", "addr", dnsAddr)
		go func() {
			if err := c.DNSServer.Start(); err != nil {
				log.Error("[EASYSS] dns forward server", "err", err)
			}
		}()
	}

	log.Info("[EASYSS] started successfully")
	// Start a fresh stats session: the process may host multiple
	// start/stop cycles (e.g. Android), so reset both the session
	// start time and all counters.
	stats.ResetStartTime()
	stats.ResetCounters()
	stats.StartSpeedMonitor()
	return c, nil
}

func (c *Core) Stop() {
	c.cleanup()
	log.Info("[EASYSS] stopped")
}

// prebindTCP verifies the given TCP address is bindable before server
// goroutines start, so listen failures (e.g. port already in use) fail
// fast with an error instead of being logged and silently ignored.
func prebindTCP(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return l.Close()
}

// prebindUDP is the UDP counterpart of prebindTCP, used by the DNS
// forward server which listens on UDP.
func prebindUDP(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	return pc.Close()
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
	// No active session anymore, so no session start time either.
	stats.ClearStartTime()
	stats.StopSpeedMonitor()
}
