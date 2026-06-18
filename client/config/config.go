package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nange/easyss/v3/config"
)

type ServerProfile struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Method   string `json:"method"`
	SNI      string `json:"sn"`
	CAPath   string `json:"ca_path"`
	Default  bool   `json:"default"`
}

type LocalConfig struct {
	SocksPort        int             `json:"socks_port"`
	HTTPPort         int             `json:"http_port"`
	BindAll          bool            `json:"bind_all"`
	DisableSysProxy  bool            `json:"disable_sys_proxy"`
	EnableForwardDNS bool            `json:"enable_forward_dns"`
	EnableTun2socks  bool            `json:"enable_tun2socks"`
	EnableQUIC       bool            `json:"enable_quic"`
	TunConfig        json.RawMessage `json:"tun_config,omitempty"`
}

type RoutingConfig struct {
	ProxyRule         string `json:"proxy_rule"`
	IPV6Rule          string `json:"ipv6_rule"`
	DirectIPsFile     string `json:"direct_ips_file"`
	DirectDomainsFile string `json:"direct_domains_file"`
}

type TransportConfig struct {
	Protocol       string `json:"protocol"`
	EndpointPrefix string `json:"endpoint_prefix"`
	ConnCountMin   int    `json:"conn_count_min"`
	ConnCountMax   int    `json:"conn_count_max"`
}

type ShaperConfig struct {
	BatchWindowMS int                `json:"batch_window_ms"`
	Cover         ShaperCoverConfig  `json:"cover"`
}

type ShaperCoverConfig struct {
	BudgetRatio float64 `json:"budget_ratio"`
}

type LogConfig struct {
	Level    string `json:"level"`
	FilePath string `json:"file_path"`
}

type ClientConfig struct {
	ConfigVersion int              `json:"version"`
	Servers       []*ServerProfile `json:"servers"`
	Local         LocalConfig      `json:"local"`
	Routing       RoutingConfig    `json:"routing"`
	Transport     TransportConfig  `json:"transport"`
	Shaper        ShaperConfig     `json:"shaper"`
	Log           LogConfig        `json:"log"`
	Timeout       int              `json:"timeout"`
	AuthUsername  string           `json:"auth_username"`
	AuthPassword  string           `json:"auth_password"`
}

func (c *ClientConfig) DefaultServer() *ServerProfile {
	for _, s := range c.Servers {
		if s.Default {
			return s
		}
	}
	if len(c.Servers) > 0 {
		return c.Servers[0]
	}
	return nil
}

func (c *ClientConfig) ServerURL() string {
	srv := c.DefaultServer()
	if srv == nil {
		return ""
	}
	return fmt.Sprintf("https://%s:%d", srv.Address, srv.Port)
}

func (c *ClientConfig) TimeoutDuration() time.Duration {
	if c.Timeout <= 0 {
		return time.Duration(config.DefaultTimeout) * time.Second
	}
	return time.Duration(c.Timeout) * time.Second
}

func (c *ClientConfig) TLSConfig() *tls.Config {
	srv := c.DefaultServer()
	if srv == nil {
		return nil
	}

	sni := srv.SNI
	if sni == "" {
		sni = srv.Address
	}

	tlsCfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	}

	if srv.CAPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(srv.CAPath)
		if err == nil && pool.AppendCertsFromPEM(pem) {
			tlsCfg.RootCAs = pool
		}
	}

	return tlsCfg
}

func (c *ClientConfig) UTLSConfig() *utls.Config {
	srv := c.DefaultServer()
	if srv == nil {
		return nil
	}

	sni := srv.SNI
	if sni == "" {
		sni = srv.Address
	}

	utlsCfg := &utls.Config{
		ServerName: sni,
		NextProtos: []string{"h2"},
	}

	if srv.CAPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(srv.CAPath)
		if err == nil && pool.AppendCertsFromPEM(pem) {
			utlsCfg.RootCAs = pool
		}
	}

	return utlsCfg
}

func LoadConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var probe struct {
		ConfigVersion int              `json:"version"`
		Servers       []*ServerProfile `json:"servers"`
		Server        string           `json:"server"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if probe.ConfigVersion != 3 || len(probe.Servers) == 0 {
		var v2 V2Config
		if err := json.Unmarshal(data, &v2); err != nil {
			return nil, err
		}
		return MigrateV2Config(v2)
	}

	var cfg ClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)

	return &cfg, nil
}

func applyDefaults(c *ClientConfig) {
	if c.Timeout <= 0 {
		c.Timeout = config.DefaultTimeout
	}
	if c.Transport.Protocol == "" {
		c.Transport.Protocol = "h2"
	}
	if c.Transport.EndpointPrefix == "" {
		c.Transport.EndpointPrefix = "/v3"
	}
	if c.Transport.ConnCountMin <= 0 {
		c.Transport.ConnCountMin = config.DefaultConnCountMin
	}
	if c.Transport.ConnCountMax <= 0 {
		c.Transport.ConnCountMax = config.DefaultConnCountMax
	}
	if c.Shaper.BatchWindowMS <= 0 {
		c.Shaper.BatchWindowMS = config.DefaultBatchWindowMS
	}
	if c.Routing.ProxyRule == "" {
		c.Routing.ProxyRule = "auto"
	}
	if c.Routing.IPV6Rule == "" {
		c.Routing.IPV6Rule = "auto"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	for _, srv := range c.Servers {
		if srv.Port == 0 {
			srv.Port = 443
		}
		if srv.Method == "" {
			srv.Method = "aes-256-gcm"
		}
	}
}

func (c *ClientConfig) Clone() *ClientConfig {
	data, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	var clone ClientConfig
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil
	}
	return &clone
}

func (c *ClientConfig) SetDefaultServerIndex(i int) {
	for j, s := range c.Servers {
		s.Default = (j == i)
	}
}

func (c *ClientConfig) ServerListAddrs() []string {
	var addrs []string
	for _, s := range c.Servers {
		addrs = append(addrs, fmt.Sprintf("%s:%d", s.Address, s.Port))
	}
	return addrs
}

func (c *ClientConfig) DefaultServerAddr() string {
	srv := c.DefaultServer()
	if srv == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", srv.Address, srv.Port)
}

func (c *ClientConfig) DefaultServerIndex() int {
	for i, s := range c.Servers {
		if s.Default {
			return i
		}
	}
	return 0
}
