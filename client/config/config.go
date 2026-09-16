package config

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

// DirectDNSServers 是用于直连（不走代理）DNS 查询的公共 DNS 服务器列表。
var DirectDNSServers = []string{"223.5.5.53:53", "119.29.29.29:53", "[2400:3200::1]:53", "[2400:3200:baba::1]:53"}

// ProxyDNSServer 是通过隧道代理 DNS 查询时使用的上游 DNS 服务器。
const ProxyDNSServer = "8.8.8.8:53"

// DefaultSystemDNS 是 TUN 模式在 Darwin 上启动时设置到系统的 DNS 服务器。
// 它取公共 DNS 地址 223.5.5.5；注意 DirectDNSServers 第一项（223.5.5.53:53）
// 去掉端口后是 223.5.5.53，与它并不相同。
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
	Protocol          string  `json:"protocol"`
	ConnCountMax      int     `json:"conn_count_max"`
	StreamThreshold   int     `json:"stream_threshold"`
	PrioritySlotRatio float64 `json:"priority_slot_ratio"`
	ConnLifetimeSec   int     `json:"conn_lifetime_sec"` // 连接的最大生命周期（秒），0 表示使用默认值
	ConnMaxBytes      int64   `json:"conn_max_bytes"`    // 连接在任一方向上承载的最大字节数，0 表示使用默认值
	// DisableWarmUp 用于禁用传输层连接池的后台预热，该预热由 runner.Run 在核心
	// 启动完成后派发（所使用的取值参见 config.WarmUpTimeout / config.WarmUpStartDelay）。
	// false 是零值，因此在该选项出现之前写入的配置文件会保持预热开启。
	DisableWarmUp bool `json:"disable_warm_up"`
}

type ShaperConfig struct {
	BatchWindowMS    int     `json:"batch_window_ms"`
	CoverBudgetRatio float64 `json:"cover_budget_ratio"`
	CoverBudgetCap   int     `json:"cover_budget_cap"`
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
	PprofEnabled  bool             `json:"pprof_enabled"`
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
		NextProtos: config.NextProtos,
	}

	if srv.CAPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(srv.CAPath)
		if err != nil {
			log.Warn("[CONFIG] load custom CA", "file", srv.CAPath, "err", err)
		} else if !pool.AppendCertsFromPEM(pem) {
			log.Warn("[CONFIG] load custom CA: no valid PEM certs", "file", srv.CAPath)
		} else {
			utlsCfg.RootCAs = pool
			log.Info("[CONFIG] loaded custom CA", "file", srv.CAPath)
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
		var s config.SimpleConfig
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		return BuildSimpleConfig(&s)
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
		c.Transport.Protocol = config.DefaultProtocol
	}
	if c.Transport.ConnCountMax <= 0 {
		c.Transport.ConnCountMax = config.DefaultConnCountMax
	}
	if c.Transport.ConnCountMax < config.MinConnCountMax {
		c.Transport.ConnCountMax = config.MinConnCountMax
	}
	if c.Transport.ConnCountMax > config.MaxConnCountMax {
		c.Transport.ConnCountMax = config.MaxConnCountMax
	}
	if c.Transport.StreamThreshold <= 0 {
		c.Transport.StreamThreshold = config.DefaultStreamThreshold
	}
	if c.Transport.StreamThreshold > config.MaxStreamThreshold {
		c.Transport.StreamThreshold = config.MaxStreamThreshold
	}
	if c.Transport.ConnLifetimeSec <= 0 {
		c.Transport.ConnLifetimeSec = config.DefaultConnLifetimeSec
	}
	if c.Transport.ConnMaxBytes <= 0 {
		c.Transport.ConnMaxBytes = config.DefaultConnMaxBytes
	}
	// shaper 设置在构建 shaper 时归一化（shaper.Config.Normalize），
	// 由它持有这些默认值与边界；在这里再保留一份副本正是导致两者偏离的原因。
	if c.Routing.ProxyRule == "" {
		c.Routing.ProxyRule = config.DefaultProxyRule
	}
	if c.Routing.IPV6Rule == "" {
		c.Routing.IPV6Rule = config.DefaultIPV6Rule
	}
	if c.Log.Level == "" {
		c.Log.Level = config.DefaultLogLevel
	}
	for _, srv := range c.Servers {
		if srv.Port == 0 {
			srv.Port = config.DefaultServerPort
		}
		if srv.Method == "" {
			srv.Method = config.DefaultMethod
		}
	}
}

// ResolveFilePaths 将配置中的相对文件路径解析为相对可执行文件目录的路径，
// 前提是这些路径无法在当前工作目录中找到。在 macOS 上应用常由 Finder/launchd
// 以 cwd=/ 启动，因此 direct.txt、proxy.txt 或 ca_path 等相对路径即使与
// 二进制/.app bundle 位于同一目录，也照样无法被找到。
func (c *ClientConfig) ResolveFilePaths() {
	c.Routing.DirectFile = util.ResolvePath(c.Routing.DirectFile)
	c.Routing.ProxyFile = util.ResolvePath(c.Routing.ProxyFile)
	for _, srv := range c.Servers {
		srv.CAPath = util.ResolvePath(srv.CAPath)
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

func ParseConfigJSON(jsonStr string) (*ClientConfig, error) {
	var cfg ClientConfig
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)
	return &cfg, nil
}

func DefaultConfig() *ClientConfig {
	cfg := &ClientConfig{
		ConfigVersion: 3,
		Local: LocalConfig{
			SocksPort: config.DefaultSocksPort,
			HTTPPort:  config.DefaultHTTPPort,
		},
	}
	applyDefaults(cfg)
	return cfg
}
