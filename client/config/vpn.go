package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

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
	// config.DefaultVPNPeerPort。
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
	// 它不进隧道、对端看不到，因此不需要与其他节点一致（见 VPNConfig 的类型注释）。
	OverlayCIDR string `json:"overlay_cidr,omitempty"`

	// DERPAddr 显式指定本节点在自己地址里通告的 DERP host:port。未配置时从被
	// derp 标记的 server 条目派生（见 ClientConfig.VPNDERPAddrs）；配置后整组
	// 节点退化成它一个——多节点请改用多个 `derp: true` 标记。
	DERPAddr string `json:"derp_addr,omitempty"`

	// Peers 是本节点要访问的对端列表。
	Peers []VPNPeer `json:"peers,omitempty"`

	// AllowClients 是允许接入本节点对端面的对端 node key 列表
	// （nodekey:... 文本格式），为空表示不限制。启用它的前提是访问侧的 client
	// key 已持久化，且运维能从访问侧的启动日志里读到自己的 nodekey。
	AllowClients []string `json:"allow_clients,omitempty"`

	// 注意：这里没有"mesh"相关字段。mesh 只存在于服务端之间（见 server.vpn 的
	// mesh_key / mesh_peers），节点侧不参与、也不需要知道。
}

// RelayOnlyEnabled 报告是否强制"只经 DERP 中继"。
//
// relay_only 缺省为 true（应对跨省 UDP QoS 的默认姿态），且 TUN 模式下必须为
// true——否则 magicsock 会建 UDP socket，其出网流量被 TUN 捕获后形成环路。
func (v VPNConfig) RelayOnlyEnabled() bool {
	return v.RelayOnly == nil || *v.RelayOnly
}

// DERPServers 返回"其 address:port 就是内嵌 DERP 位置"的全部服务端条目，保持
// 配置顺序：它们共同构成同一个 region 下的多个中继节点（见 VPNDERPAddrs）。
//
// 没有任何条目标记 derp 时回退到**当前连接的服务端**（DefaultServer），而不是
// servers[0]：内嵌 DERP 只接待经本服务端隧道送达的连接，所以"本节点实际能用的
// 中继"永远是它此刻连的那台；取 servers[0] 会在默认 server 不是第一条时派生出
// 一个永远连不上的中继地址。显式标记 derp 才能声明多节点，也才能摆脱"地址跟着
// 当前服务端变化"这一副作用。
func (c *ClientConfig) DERPServers() []*ServerProfile {
	var out []*ServerProfile
	for _, s := range c.Servers {
		if s.DERP {
			out = append(out, s)
		}
	}
	if len(out) > 0 {
		return out
	}
	if srv := c.DefaultServer(); srv != nil {
		return []*ServerProfile{srv}
	}
	return nil
}

// DERPServer 返回多节点视图里的第一个条目（单节点视图，供日志与既有调用点使用）。
func (c *ClientConfig) DERPServer() *ServerProfile {
	if servers := c.DERPServers(); len(servers) > 0 {
		return servers[0]
	}
	return nil
}

// VPNDERPAddrs 返回本节点在自己 tailcat 地址里通告的全部 DERP host:port：
// vpn.derp_addr 显式配置时就是它一个（覆盖整组节点），否则逐个 DERPServers()
// 派生。返回值按 config.CanonicalDERPAddr 规范化后去重并保持顺序（同一个中继被
// 两条服务器条目指向时只算一个节点）；没有任何可用条目时返回 nil。
func (c *ClientConfig) VPNDERPAddrs() []string {
	if c.VPN.DERPAddr != "" {
		return []string{c.VPN.DERPAddr}
	}
	var out []string
	seen := make(map[string]struct{})
	for _, srv := range c.DERPServers() {
		addr := derpAddrOf(srv)
		if addr == "" {
			continue
		}
		canonical, err := sharedconfig.CanonicalDERPAddr(addr)
		if err != nil {
			// 非法条目在这里不报错（DHCP/手写配置的容错路径与既有的
			// VPNOverlayPrefix 一致）：严格校验发生在 vpn.BuildRegion 与
			// vpnnode.NewConfig，那里能报出"第几个节点"的上下文。
			out = append(out, addr)
			continue
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// VPNDERPAddr 返回通告列表里的第一个（单节点视图；空表示没有任何可用条目，
// 调用方必须按错误处理，不能当成"用默认端口"）。
func (c *ClientConfig) VPNDERPAddr() string {
	if addrs := c.VPNDERPAddrs(); len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

// ValidateDERPServer 校验"当前连接的服务端必须是本节点声明的 DERP 中继之一"。
//
// 这条不变量不是可选的：内嵌 DERP 只接待经**本服务端**隧道送达的连接（服务端把
// 握手目标完全匹配到自己的 derp_addr 后改拨回环），因此节点实际能连上的中继只能是
// 它此刻隧道所落的那台服务端。声明列表里没有它时，中继连接会一路失败，症状是
// "VPN 一直连不上"而不是一条配置错误——所以这里当场拒绝。
//
// 没有 servers[]（或派生出空列表）时不在这里报错：那种情况下 VPN 本来就无法工作，
// 由 VPN 启动路径的"无法派生 DERP 地址"分支给出更准确的错误。列表里的地址全都解析
// 不出来时同样不在这里报错——"地址非法"由 vpnnode.NewConfig 报得更准确（它带节点
// 序号），把这种配置说成"当前服务端不在列表里"只会把人引向歧途。
func (c *ClientConfig) ValidateDERPServer() error {
	addrs := c.VPNDERPAddrs()
	if len(addrs) == 0 {
		return nil
	}
	srv := c.DefaultServer()
	if srv == nil {
		return nil
	}
	current := derpAddrOf(srv)
	canonicalCurrent, err := sharedconfig.CanonicalDERPAddr(current)
	if err != nil {
		return fmt.Errorf("vpn: cannot tell whether the current server %q is one of the DERP relays this node declares: %w", current, err)
	}
	parsed := 0
	for _, addr := range addrs {
		canonical, err := sharedconfig.CanonicalDERPAddr(addr)
		if err != nil {
			continue
		}
		parsed++
		if canonical == canonicalCurrent {
			return nil
		}
	}
	if parsed == 0 {
		return nil
	}
	return fmt.Errorf("vpn: the current server %s is not one of the DERP relays this node declares (%s): "+
		"the embedded DERP is private and every node reaches it through the easyss server it is connected to, "+
		"so the relay list must contain that server; mark the matching servers[] entry with \"derp\": true "+
		"(or set vpn.derp_addr to it) and regenerate this node's address with -show-vpn-identity",
		current, strings.Join(addrs, ", "))
}

// derpAddrOf 返回一条 server 条目的对外 host:port。
//
// 用 net.JoinHostPort 而不是 fmt.Sprintf("%s:%d")：返回值要交给
// net.SplitHostPort 拆成 HostName 与 DERPPort 写进 DERPMap，IPv6 字面量必须带
// 方括号才是合法的 host:port。
func derpAddrOf(srv *ServerProfile) string {
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
