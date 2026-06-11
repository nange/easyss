package client

import (
	cryptorand "crypto/rand"
	"math/big"
	"sync"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/transport"
	"github.com/nange/easyss/v3/transport/http2"
)

type Client struct {
	cfg       *config.ClientConfig
	router    *router.Router
	transport *http2.HTTP2Transport
	shaperCfg shaper.Config
	masterKey []byte

	mu      sync.RWMutex
	closing chan struct{}
}

func New(cfg *config.ClientConfig) (*Client, error) {
	masterKey, err := crypto.DeriveMasterKey(cfg.DefaultServer().Password)
	if err != nil {
		return nil, err
	}

	tlsCfg := cfg.TLSConfig()

	slotCount := chooseSlotCount(cfg.Transport.ConnCountMin, cfg.Transport.ConnCountMax)

	tr, err := http2.New(http2.Config{
		ServerURL: cfg.ServerURL(),
		TLSConfig: tlsCfg,
		SlotCount: slotCount,
		Timeout:   cfg.TimeoutDuration(),
	})
	if err != nil {
		return nil, err
	}

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
		closing:   make(chan struct{}),
	}, nil
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

	if c.closing != nil {
		close(c.closing)
		c.closing = nil
	}
	return c.transport.Close()
}

func (c *Client) SetProxyRule(rule string) {
	pr := router.ParseProxyRule(rule)
	c.cfg.Routing.ProxyRule = rule
	c.router.SetProxyRule(pr)
}
