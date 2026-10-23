package config

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
)

// DirectDNSServers 是直连 DNS 查询的公共 DNS 列表，IPv4 在前、IPv6 在后。顺序即优先级：
// 预解析按顺序串行尝试，在线查询并发下发取首个成功。
var DirectDNSServers = []string{
	"223.5.5.5:53",       // AliDNS
	"119.29.29.29:53",    // DNSPod
	"114.114.114.114:53", // 114DNS
	"123.123.123.123:53", // 北京联通递归 DNS
	"[2400:3200::1]:53",
	"[2400:3200:baba::1]:53",
}

const ProxyDNSServer = "8.8.8.8:53"

// DefaultSystemDNS 是写入系统解析器配置的保底裸 IPv4，等于 DirectDNSServers 的第一个 IPv4
// 项。TUN 启动时优先用 dns.PreferredSystemDNS()，都没有记录时才回退到这里。
const DefaultSystemDNS = "223.5.5.5"

// ServerProfile 描述一个服务端端点。Host 是主机名或 IP 字面量，不含端口。
type ServerProfile struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Method   string `json:"method"`
	SNI      string `json:"sn"`
	CAPath   string `json:"ca_path"`
	Default  bool   `json:"default"`

	// DERP 标记"用这条服务端的 address:port 作为内嵌 DERP 中继的主机与端口"。
	// 它同时是访问侧拨号的目标与自身地址里通告的 DERP 位置（见
	// ClientConfig.VPNDERPAddrs）。可以同时标记多条：它们共同构成同一个 region
	// 下的多个中继节点（互为冗余），但**总数不能超过 config.MaxVPNRelays**
	// （3 台，推荐 1-2 台）——超过时客户端在配置加载阶段就报错拒绝启动（见
	// ClientConfig.ValidateDERPRelays）。没有任何条目被标记时回退**当前连接的服务端**。
	//
	// 这是声明中继的唯一方式（没有 vpn.derp_addr 那样的显式覆盖项）：标记的值
	// 必须与服务端自己的 domain + listen 端口一致，否则服务端认不出那条 DERP
	// 连接（它靠完全匹配自己的对外地址把该连接改拨到回环）。
	DERP bool `json:"derp,omitempty"`
}

// UnmarshalJSON 兼容旧版完整模式配置里的 servers[].address（等价于 host）。新旧键同时出现
// 属于歧义配置，直接报错而不是静默选择其中一个。
func (s *ServerProfile) UnmarshalJSON(data []byte) error {
	type plain ServerProfile
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}

	var legacy struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}

	if legacy.Address != "" {
		if p.Host != "" {
			return fmt.Errorf(`servers[]: both "host" (%q) and deprecated "address" (%q) are set; use "host" only`,
				p.Host, legacy.Address)
		}
		p.Host = legacy.Address
	}

	*s = ServerProfile(p)
	return nil
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
	ConnMaxBytes      int64   `json:"conn_max_bytes"` // 单个连接在任一方向承载的最大字节数，0 用默认值
}

// ClientConfig 是完整模式客户端配置。
type ClientConfig struct {
	ConfigVersion int              `json:"version"`
	Servers       []*ServerProfile `json:"servers"`
	Local         LocalConfig      `json:"local"`
	Routing       RoutingConfig    `json:"routing"`
	VPN           VPNConfig        `json:"vpn"`
	Transport     TransportConfig  `json:"transport"`
	Shaper        shaper.Config    `json:"shaper"`
	Log           log.Config       `json:"log"`
	Timeout       int              `json:"timeout"`
	AuthUsername  string           `json:"auth_username"`
	AuthPassword  string           `json:"auth_password"`
	PprofEnabled  bool             `json:"pprof_enabled"`
}

// validateServers 固定服务端条目的契约：host 必填且不得含端口。冒号只在 host 是合法 IP
// 字面量（IPv6）时才允许——带端口的域名会被拼成 https://<host>:<port>:<port>，失败点离配置很远。
func (c *ClientConfig) validateServers() error {
	for i, srv := range c.Servers {
		if srv == nil {
			return fmt.Errorf("servers[%d] is null", i)
		}
		if srv.Host == "" {
			return fmt.Errorf("servers[%d].host is required", i)
		}
		if _, err := netip.ParseAddr(srv.Host); err != nil && strings.Contains(srv.Host, ":") {
			return fmt.Errorf("servers[%d].host %q must not include a port; use servers[%d].port", i, srv.Host, i)
		}
	}
	return nil
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
	return "https://" + net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
}

func (c *ClientConfig) TimeoutDuration() time.Duration {
	return config.TimeoutDuration(c.Timeout)
}

// ConnLifetimeDuration 是连接轮换前的最大存活时长，由基础超时派生（12 倍，默认 360s）。
// 刻意不可配置：单一旋钮 timeout 同时缩放空闲、拨号与轮换节奏。
func (c *ClientConfig) ConnLifetimeDuration() time.Duration {
	return config.ConnLifetime(c.TimeoutDuration())
}

// TunMTU 返回归一化后的 TUN MTU，它是设备真实 MTU 与 tun2socks netstack MTU 的共同来源。
// 再归一化一次是为了覆盖不经过 applyDefaults 的构造路径。
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
		sni = srv.Host
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
			DERPAddr    string `json:"derp_addr"`
			OverlayCIDR string `json:"overlay_cidr"`
		} `json:"vpn"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	warnOnRemovedDERPAddr(probe.VPN.DERPAddr)
	warnOnRemovedVPNOverlayCIDR(probe.VPN.OverlayCIDR)
	if probe.ConfigVersion != 3 || len(probe.Servers) == 0 {
		var s config.SimpleConfig
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		return BuildSimpleConfig(&s)
	}

	// 完整模式与 ParseConfigJSON 共用同一条解析/归一化/校验路径，否则"从文件加载"与
	// "从字符串加载"会对同一份配置给出不同结果。
	return ParseConfigJSON(string(data))
}

// normalizeHTTPPort 在 http_port 未配置（0）时由 socks_port 推导。socks_port 为 0（不启动
// 本地代理）时不推导。
func normalizeHTTPPort(c *ClientConfig) {
	if c.Local.HTTPPort == 0 && c.Local.SocksPort > 0 {
		c.Local.HTTPPort = c.Local.SocksPort + config.DefaultHTTPPortOffset
	}
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

// warnOnRemovedVPNOverlayCIDR 对配置里残留的 vpn.overlay_cidr 键告警一次。
//
// 该字段已被移除：overlay 段是**访问侧本地**给对端分配虚拟 IPv4 用的，不进隧道、
// 对端看不到，因此它是实现常量而不是配置项（见 config.DefaultVPNOverlayCIDR）。
// 残留的键不会被 json.Unmarshal 报错（未知键一律忽略），但它可能正是运维"已经把
// 这段改成别的"的原因——那段现在是死配置，实际生效的仍是常量，所以必须说出来，
// 否则"我明明改过还是冲突"会变成一个查不出来的现象。
//
// 与原值一并提示"为什么现在不能改"：这个段的唯一出路是换默认常量（一次发版所有
// 人受益），而不是每个部署各自配置。
func warnOnRemovedVPNOverlayCIDR(legacyCIDR string) {
	if legacyCIDR == "" {
		return
	}
	log.Warn("[CONFIG] vpn.overlay_cidr was removed and is ignored; "+
		"the overlay range is a local implementation constant and is not configurable",
		"overlay_cidr", legacyCIDR, "in_use", config.DefaultVPNOverlayCIDR)
}

func applyDefaults(c *ClientConfig) {
	// timeout 是全部派生超时的唯一旋钮：越界值绝不留到各消费点去兜底，否则内存中的配置与
	// 派生的值会不一致。
	c.Timeout = config.NormalizeTimeout(c.Timeout)
	// MTU 与 timeout 同理：它同时作用于 TUN 设备与 netstack，两者不一致会造成静默丢包。
	c.Local.TunMTU = config.NormalizeTunMTU(c.Local.TunMTU)
	normalizeHTTPPort(c)
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
	// shaper 设置在构建 shaper 时由 shaper.Config.Normalize 归一化并持有默认值与边界，
	// 在这里再保留一份副本正是两者偏离的原因。
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

// ResolveFilePaths 把相对路径解析为相对可执行文件目录（前提是当前工作目录找不到）。macOS
// 上应用常由 Finder/launchd 以 cwd=/ 启动，相对路径即使与二进制同目录也找不到。
func (c *ClientConfig) ResolveFilePaths() {
	c.Routing.DirectFile = util.ResolvePath(c.Routing.DirectFile)
	c.Routing.ProxyFile = util.ResolvePath(c.Routing.ProxyFile)
	for _, srv := range c.Servers {
		srv.CAPath = util.ResolvePath(srv.CAPath)
	}
}

// Clone 返回深拷贝。值拷贝覆盖标量与 json:"-" 字段，引用类型必须逐个复制；新增引用
// 字段时这里与 TestClone 一起改，否则并发读者会看到半更新的快照。
func (c *ClientConfig) Clone() *ClientConfig {
	clone := *c
	clone.Local.TunConfig = bytes.Clone(c.Local.TunConfig)
	if c.Servers != nil {
		clone.Servers = make([]*ServerProfile, len(c.Servers))
		for i, srv := range c.Servers {
			if srv == nil {
				continue
			}
			v := *srv
			clone.Servers[i] = &v
		}
	}
	if c.VPN.RelayOnly != nil {
		relayOnly := *c.VPN.RelayOnly
		clone.VPN.RelayOnly = &relayOnly
	}
	clone.VPN.Peers = slices.Clone(c.VPN.Peers)
	clone.VPN.AllowClients = slices.Clone(c.VPN.AllowClients)
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
		addrs = append(addrs, serverAddr(s))
	}
	return addrs
}

func (c *ClientConfig) DefaultServerAddr() string {
	srv := c.DefaultServer()
	if srv == nil {
		return ""
	}
	return serverAddr(srv)
}

// serverAddr 是 host:port 的唯一拼装入口：IPv6 字面量必须带方括号才是合法的 dial 地址与
// URL authority（net.JoinHostPort 负责加）。
func serverAddr(s *ServerProfile) string {
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

func (c *ClientConfig) DefaultServerIndex() int {
	for i, s := range c.Servers {
		if s.Default {
			return i
		}
	}
	return 0
}

// ParseConfigJSON 解析一份 v3 配置文本。校验口径与 LoadConfig 一致：除了默认值，
// VPN 的中继数量上限也在这里把关，使"解析出来的配置"与"启动用的配置"遵守同一组
// 硬约束（否则在两条路径之间会出现只有一条会报错的配置）。
func ParseConfigJSON(jsonStr string) (*ClientConfig, error) {
	var cfg ClientConfig
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)
	if err := cfg.validateServers(); err != nil {
		return nil, err
	}
	// tun_config 是 RawMessage，形状不对不会在 Unmarshal 阶段暴露；完整模式与简化模式
	// 必须共用 ParseTunConfig，否则同一份配置换条路径就有两种结果。
	if _, err := ParseTunConfig(cfg.Local.TunConfig); err != nil {
		return nil, err
	}
	// VPN 声明的中继数量上限：它是一条配置形状错误，与其它配置错误一样拒绝启动，
	// 而不是等到启动路径降级成"本会话 VPN 不工作"（那种降级是给运行期状态用的）。
	if err := cfg.ValidateDERPRelays(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
