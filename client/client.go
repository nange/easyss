package client

import (
	"context"
	cryptorand "crypto/rand"
	"math/big"
	"net"
	"sync"

	"github.com/nange/easyss/v3/client/config"
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
	cfg       *config.ClientConfig
	router    *router.Router
	transport *http2.HTTP2Transport
	shaperCfg shaper.Config
	masterKey []byte
	dialer    *dialer.Dialer

	mu sync.RWMutex
}

func New(cfg *config.ClientConfig) (*Client, error) {
	masterKey, err := crypto.DeriveMasterKey(cfg.DefaultServer().Password)
	if err != nil {
		return nil, err
	}

	tlsCfg := cfg.UTLSConfig()
	directDialer, directIface := newDirectDialer()

	slotCount := chooseSlotCount(cfg.Transport.ConnCountMin, cfg.Transport.ConnCountMax)

	tr, err := http2.New(http2.Config{
		ServerURL: cfg.ServerURL(),
		TLSConfig: tlsCfg,
		SlotCount: slotCount,
		Timeout:   cfg.TimeoutDuration(),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialWithConfig(ctx, cfg, directDialer, network, addr)
		},
	})
	if err != nil {
		return nil, err
	}

	log.Info("[CLIENT] transport initialized", "server_url", cfg.ServerURL(), "slots", slotCount, "server_addr", cfg.DefaultServerAddr(), "direct_iface", directIface)

	rt, err := router.New(router.Config{
		ProxyRule:         router.ParseProxyRule(cfg.Routing.ProxyRule),
		IPV6Rule:          router.ParseIPV6Rule(cfg.Routing.IPV6Rule),
		DirectIPsFile:     cfg.Routing.DirectIPsFile,
		DirectDomainsFile: cfg.Routing.DirectDomainsFile,
	})
	if err != nil {
		return nil, err
	}

	shaperCfg := shaper.Config{
		Mode:          cfg.Shaper.Mode,
		BatchWindowMS: cfg.Shaper.BatchWindowMS,
	}

	return &Client{
		cfg:       cfg,
		router:    rt,
		transport: tr,
		shaperCfg: shaperCfg,
		masterKey: masterKey,
		dialer:    directDialer,
	}, nil
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

func dialWithConfig(ctx context.Context, cfg *config.ClientConfig, d *dialer.Dialer, network, addr string) (net.Conn, error) {
	if cfg.Local.EnableTun2socks && d != nil {
		return d.DialContext(ctx, network, addr)
	}

	nd := &net.Dialer{}
	return nd.DialContext(ctx, network, addr)
}

func chooseSlotCount(minCount, maxCount int) int {
	if minCount <= 0 {
		minCount = 8
	}
	if maxCount < minCount {
		maxCount = minCount
	}
	span := maxCount - minCount + 1
	if span <= 1 {
		return minCount
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return minCount
	}
	return minCount + int(n.Int64())
}

func (c *Client) Router() *router.Router {
	return c.router
}

func (c *Client) Transport() transport.Transport {
	return c.transport
}

func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialWithConfig(ctx, c.cfg, c.dialer, network, addr)
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

	return c.transport.Close()
}

func (c *Client) SetProxyRule(rule string) {
	pr := router.ParseProxyRule(rule)
	c.cfg.Routing.ProxyRule = rule
	c.router.SetProxyRule(pr)
}
