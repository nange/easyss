package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/nange/easyss/v3/client"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

var errSocksRequired = errors.New("http proxy requires socks_port to be enabled")

// serverStartupResolveTimeout bounds each synchronous server-domain
// resolution attempt at startup. It mirrors client.serverIPV6ResolveTimeout:
// 3s is enough for a healthy network and keeps the worst-case startup delay
// short. serverStartupRetryDelay is the pause between TUN-mode retries.
// Both are vars (not consts) so tests can shorten them.
var (
	serverStartupResolveTimeout = 3 * time.Second
	serverStartupRetryDelay     = time.Second
)

// prePopulateServerDomain is a package-level var so tests can inject
// deterministic failures (same pattern as client.boundDialContext).
var prePopulateServerDomain = func(s *proxy.Socks5Server, ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
	return s.PrePopulateDNS(ctx, domain, dnsServers, requireIPv4)
}

type Core struct {
	Cfg           *config.ClientConfig
	Client        *client.Client
	SocksServer   *proxy.Socks5Server
	HTTPServer    *proxy.HTTPProxyServer
	StreamHandler *proxy.StreamHandler
	DNSServer     *dns.ForwardServer

	// StartupWarn carries a non-fatal warning detected while initializing
	// the core (e.g. a custom rule file that failed to load), so the caller
	// can surface it to the user without failing startup.
	StartupWarn error
}

func Run(cfg *config.ClientConfig) (*Core, error) {
	start := time.Now()

	cli, err := client.New(cfg)
	if err != nil {
		return nil, err
	}
	log.Info("[EASYSS] client core ready", "elapsed_ms", time.Since(start).Milliseconds())

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
	streamIdleTimeout := sharedconfig.StreamIdleTimeout(timeout)
	udpIdleTimeout := sharedconfig.UDPIdleTimeout(timeout)
	dialTimeout := sharedconfig.DialTimeout(timeout)

	streamHandler := proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, streamIdleTimeout)

	c := &Core{
		Cfg:           cfg,
		Client:        cli,
		StreamHandler: streamHandler,
		StartupWarn:   cli.StartupWarning(),
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
		if svr := cfg.DefaultServer(); svr != nil && !util.IsIP(svr.Address) {
			serverDomain = svr.Address
		}
		socksServer, err := proxy.NewSocks5Server(socksAddr, cfg.AuthUsername, cfg.AuthPassword,
			streamHandler, cli.Router(), serverDomain, method, !cfg.Local.EnableQUIC, dialTimeout, udpIdleTimeout, timeout/3, streamIdleTimeout, cli.DialContext)
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

	// The server domain must resolve for the proxied path to work at all,
	// so the resolution check belongs to core startup. A failed resolution
	// means the server is unreachable and the proxy cannot work, so it
	// aborts startup like any other fatal core error.
	if err := c.resolveServerDomain(cfg); err != nil {
		c.cleanup()
		return nil, err
	}

	log.Info("[EASYSS] started successfully", "elapsed_ms", time.Since(start).Milliseconds())
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

// resolveServerDomain pre-resolves the proxy server hostname via the direct
// DNS servers (with system fallback) and pre-seeds the DNS cache, so the
// proxied path never waits on a cold lookup. A failure is returned as a
// fatal error: without the domain resolving the server is unreachable and
// the proxy cannot work at all, so the caller aborts startup.
//
// TUN mode retries (3 attempts) because a failed pre-population there would
// deadlock TUN DNS once the system DNS is switched to the forward server;
// non-TUN mode is best-effort with a single bounded attempt. An address
// that is a literal IP needs no resolution and returns nil.
func (c *Core) resolveServerDomain(cfg *config.ClientConfig) error {
	svr := cfg.DefaultServer()
	if svr == nil || util.IsIP(svr.Address) {
		return nil
	}
	if c.SocksServer == nil {
		return nil
	}

	attempts := 1
	if cfg.Local.EnableTun2socks {
		attempts = 3
	}

	start := time.Now()
	var err error
	for i := range attempts {
		if len(config.DirectDNSServers) == 0 {
			err = errors.New("no direct dns servers configured")
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), serverStartupResolveTimeout)
		err = prePopulateServerDomain(c.SocksServer, ctx, svr.Address, config.DirectDNSServers,
			cfg.Routing.IPV6Rule != "enable")
		cancel()
		if err == nil {
			break
		}
		if i < attempts-1 {
			time.Sleep(serverStartupRetryDelay)
		}
	}

	if err != nil {
		log.Warn("[EASYSS] server domain resolution failed at startup",
			"host", svr.Address,
			"elapsed_ms", time.Since(start).Milliseconds(),
			"err", err,
		)
		return fmt.Errorf("server domain %s resolution failed: %w", svr.Address, err)
	}
	log.Info("[EASYSS] server domain resolved at startup",
		"host", svr.Address,
		"elapsed_ms", time.Since(start).Milliseconds(),
	)
	return nil
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
