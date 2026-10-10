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
// IPv4 项在前、IPv6 项在后，顺序是唯一的优先级依据：服务端域名的预解析按顺序
// 串行尝试（见 dns.Cache.PrePopulateWithFallback），在线查询则把整个列表并发
// 下发、取首个成功结果（见 dns.QueryWithBuiltinFirst 与 proxy.resolveDirectDNS）。
// 区域内可达性有差异的服务器（如北京联通 123.123.123.123）排在国家级公共 DNS 之后。
var DirectDNSServers = []string{
	"223.5.5.5:53",       // AliDNS
	"119.29.29.29:53",    // DNSPod
	"114.114.114.114:53", // 114DNS
	"123.123.123.123:53", // 北京联通递归 DNS
	"[2400:3200::1]:53",
	"[2400:3200:baba::1]:53",
}

// ProxyDNSServer 是通过隧道代理 DNS 查询时使用的上游 DNS 服务器。
const ProxyDNSServer = "8.8.8.8:53"

// DefaultSystemDNS 是写入系统解析器配置的保底裸 IPv4，等于 DirectDNSServers
// 中第一个 IPv4 项。TUN 启动时实际取值优先用 dns.PreferredSystemDNS()——本会话
// 实测可达的内置直连 DNS，其次是实测可达的系统 DNS（DHCP/内网解析器，覆盖
// "全部内置 DNS 都不可用"的网络）——两者都没有记录时才回退到这里。
const DefaultSystemDNS = "223.5.5.5"

type ServerProfile struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Method   string `json:"method"`
	SNI      string `json:"sn"`
	CAPath   string `json:"ca_path"`
	Default  bool   `json:"default"`

	// DERP 标记"用这条服务端的 address:port 作为内嵌 DERP 中继的主机与端口"。
	// 它同时是访问侧拨号的目标与自身地址里通告的 DERP 位置（见
	// ClientConfig.VPNDERPAddrs）。可以同时标记多条：它们共同构成同一个 region
	// 下的多个中继节点（互为冗余）。没有任何条目被标记时回退**当前连接的服务端**。
	//
	// 这是声明中继的唯一方式（没有 vpn.derp_addr 那样的显式覆盖项）：标记的值
	// 必须与服务端自己的 domain + listen 端口一致，否则服务端认不出那条 DERP
	// 连接（它靠完全匹配自己的对外地址把该连接改拨到回环）。
	DERP bool `json:"derp,omitempty"`
}

type LocalConfig struct {
	SocksPort        int             `json:"socks_port"`
	HTTPPort         int             `json:"http_port"`
	BindAll          bool            `json:"bind_all"`
	DisableSysProxy  bool            `json:"disable_sys_proxy"`
	EnableForwardDNS bool            `json:"enable_forward_dns"`
	EnableTun2socks  bool            `json:"enable_tun2socks"`
	EnableQUIC       bool            `json:"enable_quic"`
	TunMTU           int             `json:"tun_mtu,omitempty"`
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
	ConnMaxBytes      int64   `json:"conn_max_bytes"` // 连接在任一方向上承载的最大字节数，0 表示使用默认值
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
	VPN           VPNConfig        `json:"vpn"`
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

// TimeoutDuration 返回归一化后的基础超时：非正值取默认值，越界值钳制到
// [config.MinTimeout, config.MaxTimeout]（见 config.NormalizeTimeout）。
func (c *ClientConfig) TimeoutDuration() time.Duration {
	return config.TimeoutDuration(c.Timeout)
}

// ConnLifetimeDuration 返回传输层连接轮换前的最大存活时长，由基础超时派生
// （config.ConnLifetime = 12 倍 timeout，默认 360s）。该值刻意不可配置：
// 单一旋钮 timeout 即同时缩放空闲、拨号与轮换节奏，慢链路把 timeout 调大时
// 连接不会相对更频繁地被轮换。
func (c *ClientConfig) ConnLifetimeDuration() time.Duration {
	return config.ConnLifetime(c.TimeoutDuration())
}

// TunMTU 返回归一化后的 TUN MTU（见 config.NormalizeTunMTU）：它是 TUN 设备
// 真实 MTU 与 tun2socks netstack MTU 的共同来源，两者必须一致（见
// client/tun.Manager.engineMTU）。applyDefaults 已把合法值写回结构体，这里
// 再归一化一次是为了覆盖不经过 applyDefaults 的构造路径（简单模式构建、测试
// 以及托盘在运行期改写过的内存配置），使任何调用点都不可能拿到越界值。
func (c *ClientConfig) TunMTU() int {
	return config.NormalizeTunMTU(c.Local.TunMTU)
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
		VPN           struct {
			DERPAddr string `json:"derp_addr"`
		} `json:"vpn"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	warnOnRemovedDERPAddr(probe.VPN.DERPAddr)
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

// warnOnRemovedDERPAddr 对配置里残留的 vpn.derp_addr 键告警一次。
//
// 该字段已被移除：本节点通告的中继只从 servers[] 里带 `derp: true` 的条目派生
// （见 ClientConfig.VPNDERPAddrs），没有任何标记时回退当前连接的服务端。残留的键
// 不会被 json.Unmarshal 报错（未知键一律忽略），但它可能正是运维"以为中继在别的
// host:port"的原因——那种情况下 VPN 会按派生结果去连，症状是"一直连不上"而不是
// 一条配置错误。因此这里把它说出来。
func warnOnRemovedDERPAddr(legacyAddr string) {
	if legacyAddr == "" {
		return
	}
	log.Warn("[CONFIG] vpn.derp_addr was removed and is ignored; "+
		"the advertised relays are derived from the servers[] entries marked \"derp\": true",
		"derp_addr", legacyAddr)
}

func applyDefaults(c *ClientConfig) {
	// timeout 是全部派生超时（流空闲/UDP 空闲/拨号/DNS 响应/连接轮换）的唯一旋钮：
	// 非正值取默认值，越界值钳制到 [MinTimeout, MaxTimeout]，使内存中的配置与
	// 之后派生的值始终一致（见 config.NormalizeTimeout）。
	c.Timeout = config.NormalizeTimeout(c.Timeout)
	// MTU 与 timeout 同理：越界值绝不能留在结构体里再由各消费点各自兜底。
	// 它同时作用于 TUN 设备与 tun2socks netstack，两者不一致会造成静默丢包，
	// 因此合法性的判断只走 config.NormalizeTunMTU 这一条路径。
	c.Local.TunMTU = config.NormalizeTunMTU(c.Local.TunMTU)
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
