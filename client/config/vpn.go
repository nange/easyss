package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	sharedconfig "github.com/nange/easyss/v3/config"
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
// 这里刻意不写回任何派生值（peer_port / DERP 地址都按原样保留），派生的唯一入口
// 是下面的访问器与 vpn.NewConfig：这样"未配置"与"显式配置为其默认值"在结构体里
// 仍然可区分，命令行覆盖（--local-port）也能正确地带动 peer_port 的派生。DERP
// 地址更是只有派生一条路（见 ClientConfig.VPNDERPAddrs）：内嵌 DERP 只接待经本
// 服务端隧道送达的连接，服务端靠"握手目标完全匹配自己的对外地址"认出它，因此那个
// 地址不可能由节点自己另填一个。
//
// 这里也没有 overlay 段（曾经是 vpn.overlay_cidr）：它只决定**本机**给对端分配
// 的虚拟 IPv4，不进隧道、对端看不到、不需要与任何节点对齐，因此是个实现常量而不是
// 配置项（见 config.DefaultVPNOverlayCIDR）。残留的旧键由 LoadConfig 告警后忽略。
type VPNConfig struct {
	// Enabled 是总开关。关闭时不监听、不启 goroutine、全链路零影响。
	Enabled bool `json:"enabled"`

	// RelayOnly 强制全部经 DERP 中继、禁用节点间直连，用于应对跨省 UDP QoS。
	// 它是"默认 true"的三态字段，因此用指针表达缺省；nil 视为 true，
	// 见 RelayOnlyEnabled。
	RelayOnly *bool `json:"relay_only,omitempty"`

	// PeerPort 是本节点对端面在隧道内的端口，也是对端要拨的端口。
	// 未配置时由 socks_port 派生（见 ClientConfig.VPNPeerPort，例如 socks_port
	// 为 4080 时得到 6080）。
	PeerPort int `json:"peer_port,omitempty"`

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

// VPNDERPAddrs 返回本节点在自己 tailcat 地址里通告的全部 DERP host:port：逐个
// DERPServers() 派生（`derp: true` 标记的条目，没有任何标记时是当前服务端）。
// 返回值按 config.CanonicalDERPAddr 规范化后去重并保持顺序（同一个中继被两条
// 服务器条目指向时只算一个节点）；没有任何可用条目时返回 nil。
//
// 没有"显式覆盖"的配置项是有意的：地址里内嵌的 DERP 位置必须与服务端的对外地址
// 逐字一致（服务端靠完全匹配把它认成"来访问我的 DERP"并改拨回环），而那个对外
// 地址只由服务端的 domain 与 listen 端口决定。多节点请标记多条 `derp: true`。
func (c *ClientConfig) VPNDERPAddrs() []string {
	var out []string
	seen := make(map[string]struct{})
	for _, srv := range c.DERPServers() {
		addr := srv.HostPort()
		if addr == "" {
			continue
		}
		canonical, err := sharedconfig.CanonicalDERPAddr(addr)
		if err != nil {
			// 非法条目在这里不报错（手写配置的容错路径）：严格校验发生在
			// vpn.BuildRegion 与 vpnnode.NewConfig，那里能报出"第几个节点"的
			// 上下文。
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

// ErrCurrentServerNotDERPRelay 标记"当前运行的服务器不能作为本节点的 DERP 中继"
// （见 ValidateDERPServerAddr）。
//
// 它需要身份：这个状态的用户可见表现是"VPN 连不上对端"，而原因是一条配置事实。
// 调用方（runner → 托盘的启动通知）用 errors.Is 判定它，把"VPN 功能不生效"直接
// 告诉用户，而不是让人去翻日志里那句英文。
var ErrCurrentServerNotDERPRelay = errors.New("vpn: the current server is not a usable DERP relay of this node")

// ValidateDERPServerAddr 校验 current（**当前实际在运行**的那台服务器的 host:port）
// 是本节点声明的 DERP 中继之一。
//
// 这条不变量不是可选的：内嵌 DERP 只接待经**本服务端**隧道送达的连接（服务端把
// 握手目标完全匹配到自己的对外 DERP 地址后改拨回环），因此节点实际能连上的中继只能是
// 它此刻隧道所落的那台服务端。声明列表里没有它时，中继连接会一路失败，症状是
// "VPN 一直连不上"而不是一条配置错误——所以这里当场拒绝。
//
// current 是显式入参，刻意不在内部取 DefaultServer()：default 标记表示"下次启动用
// 哪台"，托盘切换、失败回滚与自更新重启都会改写它，而正在跑的会话可能仍停在旧的那台
// 上。判据必须跟着实际在跑的那台走（runner 用会话快照里解析出的 Core.ServerAddr）。
//
// 没有 servers[]（或派生出空列表）时不在这里报错：那种情况下 VPN 本来就无法工作，
// 由 VPN 启动路径的"无法派生 DERP 地址"分支给出更准确的错误。列表里的地址全都解析
// 不出来、或 current 本身无法解析时同样不在这里报错——"地址非法"由 vpnnode.NewConfig
// 报得更准确（它带节点序号），把这种配置说成"当前服务端不在列表里"只会把人引向歧途。
func (c *ClientConfig) ValidateDERPServerAddr(current string) error {
	addrs := c.VPNDERPAddrs()
	if len(addrs) == 0 {
		return nil
	}
	if current == "" {
		return nil
	}
	canonicalCurrent, err := sharedconfig.CanonicalDERPAddr(current)
	if err != nil {
		return fmt.Errorf("%w: cannot tell whether %q is one of them: %v",
			ErrCurrentServerNotDERPRelay, current, err)
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
	return fmt.Errorf("%w: %s is not one of the relays this node declares (%s): "+
		"the embedded DERP is private and every node reaches it through the easyss server it is connected to, "+
		"so the relay list must contain that server; mark the matching servers[] entry with \"derp\": true, "+
		"then hand the address printed by \"easyss vpn identity\" to every peer: "+
		"the advertised relay set is part of the address, so peers holding the old address list no longer match",
		ErrCurrentServerNotDERPRelay, current, strings.Join(addrs, ", "))
}

// ValidateDERPRelays 校验本节点声明的内嵌 DERP 中继数量不超过
// sharedconfig.MaxVPNRelays。
//
// 与 ValidateDERPServerAddr（判定"当前服务端是否在声明的列表里"）不同，这是一条
// **配置形状**错误：越限的配置没有任何可工作的形态。中继之间必须全互联
// （server.vpn.mesh_peers 列出其余每一台），而节点地址里内嵌的正是这一组中继、
// 且必须与每个对端的集合相等，所以第 4 台既进不了地址，也没法与其余中继互通。
// 因此它由 LoadConfig 在启动阶段直接拒绝（与其它配置错误一样让进程退出），而不是
// 降到"本会话 VPN 不工作"——后者会让用户以为只是网络问题。
//
// 只在 vpn.enabled 时校验：未启用的 VPN 不参与运行期，derp 标记此时没有任何效果，
// 不该阻止客户端启动（与 server.vpn 的校验同一条原则）。
//
// 计数口径与 VPNDERPAddrs 一致：只数**不同的**中继（规范化后去重，同一个中继被
// 两条条目指向时只算一个）；地址本身非法的条目不在这里报错——"地址非法"由
// vpnnode.NewConfig 带节点序号报出，在这里再报一次只会掩盖真正的原因。
func (c *ClientConfig) ValidateDERPRelays() error {
	if !c.VPN.Enabled {
		return nil
	}
	marked := 0
	addrs := make([]string, 0, len(c.Servers))
	seen := make(map[string]struct{}, len(c.Servers))
	for _, srv := range c.Servers {
		if srv == nil || !srv.DERP {
			continue
		}
		marked++
		addr := srv.HostPort()
		canonical, err := sharedconfig.CanonicalDERPAddr(addr)
		if err != nil {
			continue
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		addrs = append(addrs, addr)
	}
	if len(addrs) <= sharedconfig.MaxVPNRelays {
		return nil
	}
	return fmt.Errorf("servers[] has %d entries marked with \"derp\": true, which declare %d DERP relays (%s), "+
		"but at most %d relays are supported (1-2 are recommended): the relays of a region must be meshed with "+
		"one another and the whole set is embedded in this node's address, so delete the extra entries or remove "+
		"their \"derp\": true mark",
		marked, len(addrs), strings.Join(addrs, ", "), sharedconfig.MaxVPNRelays)
}

// HostPort 返回一条 server 条目的对外 host:port（空地址返回 ""）。
//
// 用 net.JoinHostPort 而不是 fmt.Sprintf("%s:%d")：返回值要交给
// net.SplitHostPort 拆成 HostName 与 DERPPort 写进 DERPMap，IPv6 字面量必须带
// 方括号才是合法的 host:port；它也必须是 ValidateDERPServerAddr 能比较的形态。
func (s *ServerProfile) HostPort() string {
	if s == nil || s.Address == "" {
		return ""
	}
	// applyDefaults 已经为 servers[].port 补过默认值，这里再兜一次是为了覆盖
	// 不经过它与 BuildSimpleConfig 的构造路径（移动端、测试）。
	port := s.Port
	if port <= 0 {
		port = sharedconfig.DefaultServerPort
	}
	return net.JoinHostPort(s.Address, strconv.Itoa(port))
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
