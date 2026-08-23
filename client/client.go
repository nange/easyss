package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/transport"
	"github.com/nange/easyss/v3/transport/http2"
	"github.com/nange/easyss/v3/util"
	"github.com/xjasonlyu/tun2socks/v2/dialer"
)

type Client struct {
	cfg           *config.ClientConfig
	router        *router.Router
	transport     *http2.HTTP2Transport
	shaperCfg     shaper.Config
	masterKey     []byte
	dialer        atomic.Pointer[dialer.Dialer]
	closeIdleDone chan struct{}
	closeOnce     sync.Once

	mu sync.RWMutex
}

func New(cfg *config.ClientConfig) (*Client, error) {
	masterKey, err := crypto.DeriveMasterKey(cfg.DefaultServer().Password)
	if err != nil {
		return nil, err
	}

	rt, err := router.New(router.Config{
		ProxyRule:  router.ParseProxyRule(cfg.Routing.ProxyRule),
		IPV6Rule:   router.ParseIPV6Rule(cfg.Routing.IPV6Rule),
		DirectFile: cfg.Routing.DirectFile,
		ProxyFile:  cfg.Routing.ProxyFile,
	})
	if err != nil {
		return nil, err
	}

	serverIPV6 := ""
	ipv6Networking := false
	if router.ParseIPV6Rule(cfg.Routing.IPV6Rule) != router.IPV6RuleDisable {
		serverIPV6 = resolveServerIPV6(cfg)
		ipv6Networking = detectIPV6Networking()
	}
	rt.SetIPV6Info(ipv6Networking, serverIPV6)

	log.Info("[CLIENT] router initialized",
		"proxy_rule", cfg.Routing.ProxyRule,
		"ipv6_rule", cfg.Routing.IPV6Rule,
		"ipv6_networking", ipv6Networking,
		"server_ipv6", serverIPV6,
	)

	tlsCfg := cfg.UTLSConfig()
	directDialer, directIface := newDirectDialer()

	shaperCfg := shaper.Config{
		BatchWindowMS: cfg.Shaper.BatchWindowMS,
		Cover: shaper.CoverConfig{
			BudgetRatio: cfg.Shaper.CoverBudgetRatio,
			BudgetCap:   cfg.Shaper.CoverBudgetCap,
		},
	}

	client := &Client{
		cfg:           cfg,
		router:        rt,
		shaperCfg:     shaperCfg,
		masterKey:     masterKey,
		closeIdleDone: make(chan struct{}),
	}
	client.dialer.Store(directDialer)

	probeToken, err := crypto.ProbeToken(masterKey)
	if err != nil {
		return nil, fmt.Errorf("probe token: %w", err)
	}

	tr, err := http2.New(http2.Config{
		ServerURL:         cfg.ServerURL(),
		TLSConfig:         tlsCfg,
		MaxSlotCount:      cfg.Transport.ConnCountMax,
		StreamThreshold:   cfg.Transport.StreamThreshold,
		PrioritySlotRatio: cfg.Transport.PrioritySlotRatio,
		ConnLifetime:      time.Duration(cfg.Transport.ConnLifetimeSec) * time.Second,
		ConnMaxBytes:      cfg.Transport.ConnMaxBytes,
		Timeout:           cfg.TimeoutDuration(),
		ProbeToken:        probeToken,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialWithConfig(ctx, cfg, client.dialer.Load(), rt, network, addr)
		},
	})
	if err != nil {
		return nil, err
	}

	client.transport = tr

	log.Info("[CLIENT] transport initialized", "server_url", cfg.ServerURL(), "max_slots", cfg.Transport.ConnCountMax, "stream_threshold", cfg.Transport.StreamThreshold, "server_addr", cfg.DefaultServerAddr(), "direct_iface", directIface)

	go client.closeIdleLoop()

	return client, nil
}

func newDirectDialer() (*dialer.Dialer, string) {
	_, dev, err := util.SysGatewayAndDevice()
	if err != nil || dev == "" {
		log.Warn("[CLIENT] detect default interface failed", "err", err)
		return dialer.New(), ""
	}

	iface, err := net.InterfaceByName(dev)
	if err != nil {
		log.Warn("[CLIENT] load default interface failed", "name", dev, "err", err)
		return dialer.New(), ""
	}

	return dialer.New(dialer.WithBindToInterface(iface)), dev
}

func dialWithConfig(ctx context.Context, cfg *config.ClientConfig, d *dialer.Dialer, rt *router.Router, network, addr string) (net.Conn, error) {
	if rt.ShouldIPV6Disable() {
		switch network {
		case "tcp":
			network = "tcp4"
		case "udp":
			network = "udp4"
		}
	}

	if cfg.Local.EnableTun2socks && d != nil {
		// Force specific IP version so the direct dialer's socket-binding
		// (IP_BOUND_IF) is applied. The dialer only handles "tcp4"/"udp4",
		// not dual-stack "tcp"/"udp".
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil {
				if ip.To4() != nil {
					switch network {
					case "tcp":
						network = "tcp4"
					case "udp":
						network = "udp4"
					}
				} else {
					switch network {
					case "tcp":
						network = "tcp6"
					case "udp":
						network = "udp6"
					}
				}
			}
		}
		return d.DialContext(ctx, network, addr)
	}

	nd := &net.Dialer{
		KeepAlive: cfg.TimeoutDuration(),
	}
	return nd.DialContext(ctx, network, addr)
}

func resolveServerIPV6(cfg *config.ClientConfig) string {
	svr := cfg.DefaultServer()
	if svr == nil {
		return ""
	}
	if ip := net.ParseIP(svr.Address); ip != nil {
		if ip.To4() == nil {
			return svr.Address
		}
		return ""
	}

	if dns.BuiltinDNSAvailable() {
		reachable := false
		for _, dnsServer := range config.DirectDNSServers {
			ips, err := dns.LookupIPV6From(dnsServer, svr.Address)
			if err != nil {
				continue
			}
			// the server answered (possibly NODATA), so the builtin dns
			// servers are reachable
			reachable = true
			if len(ips) == 0 {
				continue
			}
			dns.MarkBuiltinDNSAvailable()
			return ips[0].String()
		}
		if !reachable {
			dns.MarkBuiltinDNSUnavailable()
			log.Warn("[CLIENT] all builtin direct dns servers failed to resolve server ipv6, fallback to system dns", "server", svr.Address)
		}
	}

	// fallback to the system dns servers when all builtin direct dns servers
	// are unavailable
	for _, dnsServer := range dns.SystemDNSServers() {
		ips, err := dns.LookupIPV6From(dnsServer, svr.Address)
		if err != nil || len(ips) == 0 {
			continue
		}
		return ips[0].String()
	}
	log.Warn("[CLIENT] failed to resolve server ipv6 via all direct and system dns servers", "server", svr.Address)
	return ""
}

func detectIPV6Networking() bool {
	_, _, err := util.SysGatewayAndDeviceV6()
	return err == nil
}

func (c *Client) Router() *router.Router {
	return c.router
}

func (c *Client) Transport() transport.Transport {
	return c.transport
}

func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialWithConfig(ctx, c.cfg, c.dialer.Load(), c.router, network, addr)
}

func (c *Client) MasterKey() []byte {
	return c.masterKey
}

func (c *Client) ShaperConfig() shaper.Config {
	return c.shaperCfg
}

func (c *Client) Config() *config.ClientConfig {
	return c.cfg
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close is not idempotent by contract (the transport cannot be
	// reopened), but a second call must not panic by closing the channel
	// twice.
	c.closeOnce.Do(func() { close(c.closeIdleDone) })
	return c.transport.Close()
}

func (c *Client) closeIdleLoop() {
	ticker := time.NewTicker(8 * c.cfg.TimeoutDuration())
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.transport.CloseIdle()
		case <-c.closeIdleDone:
			return
		}
	}
}

func (c *Client) SetProxyRule(rule string) {
	pr := router.ParseProxyRule(rule)
	c.cfg.Routing.ProxyRule = rule
	c.router.SetProxyRule(pr)
}

// DirectDialer returns the dialer that binds to the physical network
// interface, used to bypass TUN when TUN mode is active.
func (c *Client) DirectDialer() *dialer.Dialer {
	return c.dialer.Load()
}

// SetDirectDialer replaces the transport's direct dialer. Used after
// a server switch to preserve the original dialer that was created
// before TUN routes were installed.
func (c *Client) SetDirectDialer(d *dialer.Dialer) {
	c.dialer.Store(d)
}
