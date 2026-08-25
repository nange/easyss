package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-netroute"
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
	bound         atomic.Value // boundIface: the interface the direct dialer is bound to
	closeIdleDone chan struct{}
	closeOnce     sync.Once

	mu sync.RWMutex
}

// boundIface records the interface the direct dialer is currently bound to,
// so the refresh loop can detect a change (name or index) and rebuild it.
type boundIface struct {
	name  string
	index int
}

// detectDialIface returns the interface that TUN-mode direct dials should be
// bound to: the system's default-route interface. It probes a destination in
// 0.0.0.0/8, which the easyss TUN routes never cover (the darwin create
// script starts at 1.0.0.0/8), so the lookup yields the physical default
// interface even while TUN routes are active — binding to the easyss TUN
// device itself would create a routing loop. Overridable in tests.
var detectDialIface = func() (*net.Interface, error) {
	r, err := netroute.New()
	if err != nil {
		return nil, err
	}
	iface, _, _, err := r.Route(net.IPv4(0, 0, 0, 1))
	if err != nil {
		return nil, err
	}
	if iface == nil {
		return nil, errors.New("no interface for default route")
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("default interface %s is down", iface.Name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("read addresses of %s: %w", iface.Name, err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.IsGlobalUnicast() {
			return iface, nil
		}
	}
	return nil, fmt.Errorf("default interface %s has no global unicast address", iface.Name)
}

// boundDialContext dials through the interface-bound direct dialer. It is a
// package-level var so tests can inject failures deterministically.
var boundDialContext = func(c *Client, ctx context.Context, network, addr string) (net.Conn, error) {
	return c.dialer.Load().DialContext(ctx, network, addr)
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
	client.bound.Store(boundIface{})

	directIface := ""
	iface, err := detectDialIface()
	if err != nil {
		log.Warn("[CLIENT] detect default interface failed", "err", err)
		client.dialer.Store(dialer.New())
	} else {
		client.dialer.Store(dialer.New(dialer.WithBindToInterface(iface)))
		client.bound.Store(boundIface{name: iface.Name, index: iface.Index})
		directIface = iface.Name
	}

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
			return client.dialWithConfig(ctx, network, addr)
		},
	})
	if err != nil {
		return nil, err
	}

	client.transport = tr

	log.Info("[CLIENT] transport initialized", "server_url", cfg.ServerURL(), "max_slots", cfg.Transport.ConnCountMax, "stream_threshold", cfg.Transport.StreamThreshold, "server_addr", cfg.DefaultServerAddr(), "direct_iface", directIface)

	go client.closeIdleLoop()
	go client.dialerRefreshLoop()

	return client, nil
}

// dialWithConfig dials with the interface-bound direct dialer when TUN mode
// is active (so the socket bypasses the TUN device), falling back to a plain
// net.Dialer otherwise. A failure that looks like a stale interface binding
// (sleep/wake, network switch) triggers a one-shot dialer refresh and retry.
func (c *Client) dialWithConfig(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.router.ShouldIPV6Disable() {
		switch network {
		case "tcp":
			network = "tcp4"
		case "udp":
			network = "udp4"
		}
	}

	if c.cfg.Local.EnableTun2socks && c.dialer.Load() != nil {
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

		conn, err := boundDialContext(c, ctx, network, addr)
		if err == nil || !isInterfaceStaleError(err) {
			return conn, err
		}

		// The bound interface went stale (sleep/wake, network switch): the
		// interface captured at startup no longer routes. Re-detect the
		// default interface, rebuild the dialer and retry once.
		log.Warn("[CLIENT] direct dial failed, refreshing interface binding", "addr", addr, "err", err)
		if c.refreshDirectDialer() {
			return boundDialContext(c, ctx, network, addr)
		}
		return conn, err
	}

	nd := &net.Dialer{
		KeepAlive: c.cfg.TimeoutDuration(),
	}
	return nd.DialContext(ctx, network, addr)
}

// refreshDirectDialer re-detects the default interface and rebuilds the
// interface-bound direct dialer when the binding changed (name or index). It
// reports whether the dialer was replaced. On detection failure the existing
// dialer is kept so a transient network state cannot degrade connectivity
// further.
func (c *Client) refreshDirectDialer() bool {
	iface, err := detectDialIface()
	if err != nil {
		log.Warn("[CLIENT] refresh direct dialer: detect interface failed", "err", err)
		return false
	}

	prev, _ := c.bound.Load().(boundIface)
	if prev.name == iface.Name && prev.index == iface.Index {
		return false
	}

	c.dialer.Store(dialer.New(dialer.WithBindToInterface(iface)))
	c.bound.Store(boundIface{name: iface.Name, index: iface.Index})
	log.Info("[CLIENT] direct dialer rebound",
		"iface", iface.Name, "index", iface.Index,
		"prev_iface", prev.name, "prev_index", prev.index)
	return true
}

// dialerRefreshLoop periodically re-detects the default interface so the
// direct dialer's interface binding survives sleep/wake and network changes:
// on macOS the interface captured at startup can go stale after the machine
// wakes on a different network, breaking every direct dial until restart.
// Only runs while TUN mode is active (the bound dialer is unused otherwise).
func (c *Client) dialerRefreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if c.cfg.Local.EnableTun2socks {
				c.refreshDirectDialer()
			}
		case <-c.closeIdleDone:
			return
		}
	}
}

// isInterfaceStaleError reports whether err looks like the bound interface
// went stale (interface removed, down, or unreachable), so the dialer can be
// rebuilt and the dial retried.
func isInterfaceStaleError(err error) bool {
	if err == nil {
		return false
	}
	for _, e := range []error{
		syscall.ENETDOWN,
		syscall.ENODEV,
		syscall.ENETUNREACH,
		syscall.EHOSTUNREACH,
		syscall.EINVAL,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
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
	return c.dialWithConfig(ctx, network, addr)
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
// before TUN routes were installed. The recorded binding is reset so the
// next refresh re-detects the current default interface.
func (c *Client) SetDirectDialer(d *dialer.Dialer) {
	c.dialer.Store(d)
	c.bound.Store(boundIface{})
}
