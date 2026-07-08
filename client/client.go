package client

import (
	"context"
	"net"
	"sync"
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
	cfg            *config.ClientConfig
	router         *router.Router
	transport      *http2.HTTP2Transport
	shaperCfg      shaper.Config
	masterKey      []byte
	dialer         *dialer.Dialer
	latencyTracker *LatencyTracker
	closeIdleDone  chan struct{}

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

	tr, err := http2.New(http2.Config{
		ServerURL:       cfg.ServerURL(),
		TLSConfig:       tlsCfg,
		MaxSlotCount:    cfg.Transport.ConnCountMax,
		StreamThreshold: cfg.Transport.StreamThreshold,
		Timeout:         cfg.TimeoutDuration(),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialWithConfig(ctx, cfg, directDialer, rt, network, addr)
		},
	})
	if err != nil {
		return nil, err
	}

	log.Info("[CLIENT] transport initialized", "server_url", cfg.ServerURL(), "max_slots", cfg.Transport.ConnCountMax, "stream_threshold", cfg.Transport.StreamThreshold, "server_addr", cfg.DefaultServerAddr(), "direct_iface", directIface)

	shaperCfg := shaper.Config{
		BatchWindowMS: cfg.Shaper.BatchWindowMS,
		Cover: shaper.CoverConfig{
			BudgetRatio: cfg.Shaper.CoverBudgetRatio,
		},
	}

	client := &Client{
		cfg:            cfg,
		router:         rt,
		transport:      tr,
		shaperCfg:      shaperCfg,
		masterKey:      masterKey,
		dialer:         directDialer,
		latencyTracker: NewLatencyTracker(time.Duration(cfg.LatencyOffsetMS) * time.Millisecond),
		closeIdleDone:  make(chan struct{}),
	}

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

	for _, dnsServer := range config.DirectDNSServers {
		ips, err := dns.LookupIPV6From(dnsServer, svr.Address)
		if err != nil || len(ips) == 0 {
			continue
		}
		return ips[0].String()
	}
	log.Warn("[CLIENT] failed to resolve server ipv6 via all direct dns servers", "server", svr.Address)
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
	return dialWithConfig(ctx, c.cfg, c.dialer, c.router, network, addr)
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

func (c *Client) LatencyTracker() *LatencyTracker {
	return c.latencyTracker
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	close(c.closeIdleDone)
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
