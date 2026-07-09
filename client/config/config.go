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

// DirectDNSServers are the public DNS servers used for direct (non-proxied) DNS lookups.
var DirectDNSServers = []string{"223.5.5.53:53", "119.29.29.29:53", "[2400:3200::1]:53", "[2400:3200:baba::1]:53"}

// ProxyDNSServer is the upstream DNS server used when proxying DNS queries through the tunnel.
const ProxyDNSServer = "8.8.8.8:53"

// DefaultSystemDNS is the DNS server set on the system when TUN mode starts on Darwin.
// It corresponds to the first entry of DirectDNSServers without the port.
const DefaultSystemDNS = "223.5.5.5"

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
	ProxyRule  string `json:"proxy_rule"`
	IPV6Rule   string `json:"ipv6_rule"`
	DirectFile string `json:"direct_file"`
	ProxyFile  string `json:"proxy_file"`
}

type TransportConfig struct {
	Protocol        string `json:"protocol"`
	EndpointPrefix  string `json:"endpoint_prefix"`
	ConnCountMax    int    `json:"conn_count_max"`
	StreamThreshold int    `json:"stream_threshold"`
}

type ShaperConfig struct {
	BatchWindowMS    int     `json:"batch_window_ms"`
	CoverBudgetRatio float64 `json:"cover_budget_ratio"`
}

type LogConfig struct {
	Level    string `json:"level"`
	FilePath string `json:"file_path"`
}

type ClientConfig struct {
	ConfigVersion   int              `json:"version"`
	Servers         []*ServerProfile `json:"servers"`
	Local           LocalConfig      `json:"local"`
	Routing         RoutingConfig    `json:"routing"`
	Transport       TransportConfig  `json:"transport"`
	Shaper          ShaperConfig     `json:"shaper"`
	Log             LogConfig        `json:"log"`
	Timeout         int              `json:"timeout"`
	AuthUsername    string           `json:"auth_username"`
	AuthPassword    string           `json:"auth_password"`
	PprofEnabled    bool             `json:"pprof_enabled"`
	LatencyOffsetMS int              `json:"latency_offset_ms"`
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
	if c.Transport.ConnCountMax <= 0 {
		c.Transport.ConnCountMax = config.DefaultConnCountMax
	}
	if c.Transport.StreamThreshold <= 0 {
		c.Transport.StreamThreshold = config.DefaultStreamThreshold
	}
	if c.Shaper.BatchWindowMS <= 0 {
		c.Shaper.BatchWindowMS = config.DefaultBatchWindowMS
	}
	if c.LatencyOffsetMS <= 0 {
		c.LatencyOffsetMS = 50
	}
	if c.Shaper.BatchWindowMS > 10 {
		c.Shaper.BatchWindowMS = 10
	}
	if c.Shaper.CoverBudgetRatio < 0 || c.Shaper.CoverBudgetRatio > 1 {
		c.Shaper.CoverBudgetRatio = 0.05
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

func DefaultConfig() *ClientConfig {
	cfg := &ClientConfig{
		ConfigVersion: 3,
		Local: LocalConfig{
			SocksPort: 2080,
			HTTPPort:  3080,
		},
	}
	applyDefaults(cfg)
	return cfg
}
