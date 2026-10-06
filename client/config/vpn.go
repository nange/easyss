package config

import (
	"net"
	"net/netip"
	"strconv"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// VPNPeer 是一个对端节点在配置里的引用。
//
// 名字与地址是两件事：HostName 是应用里书写的名字（http://b:8080/、ssh user@b），
// 只存在于访问侧本地；Address 是对端的 tailcat 地址，是唯一的跨节点凭据。
type VPNPeer struct {
	HostName string `json:"host_name"`
	Address  string `json:"address"`

	// Port 是对端"对端面"在隧道内的端口，未配置时取
	// config.DefaultVPNPeerPort（详见 docs/vpn-design.md 4.3）。
	Port int `json:"port,omitempty"`
}

// VPNConfig 恰好持有客户端配置文件 "vpn" 键下的全部字段。
//
// 这里刻意不写回任何派生值（peer_port / overlay_cidr / derp_addr 都按原样保留），
// 派生的唯一入口是下面的访问器与 vpn.NewConfig：这样"未配置"与"显式配置为其
// 默认值"在结构体里仍然可区分，命令行覆盖（--local-port）也能正确地带动
// peer_port 的派生。校验与报错集中在 vpn.NewConfig，配置层只负责形状。
type VPNConfig struct {
	// Enabled 是总开关。关闭时不监听、不启 goroutine、全链路零影响。
	Enabled bool `json:"enabled"`

	// RelayOnly 强制全部经 DERP 中继、禁用节点间直连，用于应对跨省 UDP QoS。
	// 它是"默认 true"的三态字段，因此用指针表达缺省；nil 视为 true，
	// 见 RelayOnlyEnabled。
	RelayOnly *bool `json:"relay_only,omitempty"`

	// PeerPort 是本节点对端面在隧道内的端口，也是对端要拨的端口。
	// 未配置时由 socks_port 派生（见 ClientConfig.VPNPeerPort）。
	PeerPort int `json:"peer_port,omitempty"`

	// OverlayCIDR 是访问侧**本地**给对端分配的 overlay 虚拟 IPv4 段。
	// 它不进隧道、对端看不到，因此不需要与其他节点一致（见 VPNConfig 的类型注释
	// 与 docs/vpn-design.md 5.1）。
	OverlayCIDR string `json:"overlay_cidr,omitempty"`

	// DERPAddr 是本节点在自己地址里通告的 DERP host:port。未配置时从被 derp
	// 标记的 server 条目派生（见 ClientConfig.VPNDERPAddr）。
	DERPAddr string `json:"derp_addr,omitempty"`

	// Peers 是本节点要访问的对端列表。
	Peers []VPNPeer `json:"peers,omitempty"`

	// AllowClients 是允许接入本节点对端面的对端 node key 列表
	// （nodekey:... 文本格式），为空表示不限制。启用它的前提是访问侧的 client
	// key 已持久化，且运维能从访问侧的启动日志里读到自己的 nodekey。
	AllowClients []string `json:"allow_clients,omitempty"`
}

// RelayOnlyEnabled 报告是否强制"只经 DERP 中继"。
//
// relay_only 缺省为 true（应对跨省 UDP QoS 的默认姿态），且 TUN 模式下必须为
// true——否则 magicsock 会建 UDP socket，其出网流量被 TUN 捕获后形成环路
// （见 docs/vpn-design.md 8.1）。
func (v VPNConfig) RelayOnlyEnabled() bool {
	return v.RelayOnly == nil || *v.RelayOnly
}

// DERPServer 返回"其 address:port 就是内嵌 DERP 位置"的那条服务端条目：
// 第一条被 derp 标记的条目；没有任何条目标记时回退 servers[0]。
//
// 这里刻意不使用 DefaultServer()：DERP 中继是谁，与"代理走哪条 server"是两个
// 独立的选择。若跟着 default 标记走，用户切换默认 server 会静默改掉本节点对外
// 通告的地址，而每个对端都要跟着重新配置。要换中继就显式标记 derp。
func (c *ClientConfig) DERPServer() *ServerProfile {
	for _, s := range c.Servers {
		if s.DERP {
			return s
		}
	}
	if len(c.Servers) > 0 {
		return c.Servers[0]
	}
	return nil
}

// VPNDERPAddr 返回本节点在自己 tailcat 地址里通告的 DERP host:port：
// vpn.derp_addr 优先，未配置时从 DERPServer() 派生；没有可用的 server 条目时
// 返回空串（调用方必须按错误处理，不能当成"用默认端口"）。
func (c *ClientConfig) VPNDERPAddr() string {
	if c.VPN.DERPAddr != "" {
		return c.VPN.DERPAddr
	}
	return c.derpAddrFromServers()
}

// derpAddrFromServers 从 servers[] 派生 DERP 的对外 host:port。
//
// 用 net.JoinHostPort 而不是 fmt.Sprintf("%s:%d")：返回值要交给
// net.SplitHostPort 拆成 HostName 与 DERPPort 写进 DERPMap，IPv6 字面量必须带
// 方括号才是合法的 host:port。
func (c *ClientConfig) derpAddrFromServers() string {
	srv := c.DERPServer()
	if srv == nil || srv.Address == "" {
		return ""
	}
	// applyDefaults 已经为 servers[].port 补过默认值，这里再兜一次是为了覆盖
	// 不经过它与 BuildSimpleConfig 的构造路径（移动端、测试）。
	port := srv.Port
	if port <= 0 {
		port = sharedconfig.DefaultServerPort
	}
	return net.JoinHostPort(srv.Address, strconv.Itoa(port))
}

// VPNPeerPort 返回归一化后的 vpn.peer_port（见 config.NormalizeVPNPeerPort）：
// 未配置时从 socks_port 派生，越界时回退 config.DefaultVPNPeerPort。
//
// 派生放在访问器而不是 applyDefaults 里，是为了让命令行覆盖（--local-port）能
// 正确地带动它：applyDefaults 在覆盖之前就已经跑过，写回结构体会把"按旧
// socks_port 派生"的结果冻结下来。
func (c *ClientConfig) VPNPeerPort() int {
	return sharedconfig.NormalizeVPNPeerPort(c.VPN.PeerPort, c.Local.SocksPort)
}

// VPNOverlayPrefix 返回归一化后的 overlay 段（见 config.ParseVPNOverlayCIDR）。
//
// 配置非法时回退默认段并记录警告：访问器无法返回错误，严格校验（直接让启动
// 失败）发生在 vpn.NewConfig。
func (c *ClientConfig) VPNOverlayPrefix() netip.Prefix {
	p, err := sharedconfig.ParseVPNOverlayCIDR(c.VPN.OverlayCIDR)
	if err != nil {
		log.Warn("[CONFIG] invalid vpn.overlay_cidr, falling back to default",
			"overlay_cidr", c.VPN.OverlayCIDR, "default", sharedconfig.DefaultVPNOverlayCIDR, "err", err)
		return sharedconfig.DefaultVPNOverlayPrefix()
	}
	return p
}
