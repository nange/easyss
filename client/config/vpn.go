package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/nange/easyss/v3/config"
)

// VPNPeer 是配置里对一个对端节点的引用：HostName 只在访问侧本地使用，Address 是
// 对端的 tailcat 地址、唯一的跨节点凭据。
type VPNPeer struct {
	HostName string `json:"host_name"`
	Address  string `json:"address"`

	// Port 是对端"对端面"在隧道内的端口，未配置时取
	// config.DefaultVPNPeerPort。
	Port int `json:"port,omitempty"`
}

// VPNConfig 持有客户端配置 "vpn" 键下的全部字段，不写回任何派生值：peer_port 由
// 访问器按当前 socks_port 派生（命令行覆盖也能生效），DERP 地址只能派生（见
// VPNDERPAddrs）；overlay 段是实现常量而非配置项（config.DefaultVPNOverlayCIDR）。
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

// RelayOnlyEnabled 报告是否强制只经 DERP 中继：缺省为 true，TUN 下必须为 true，
// 否则 magicsock 建的 UDP socket 会被 TUN 捕获形成环路。
func (v VPNConfig) RelayOnlyEnabled() bool {
	return v.RelayOnly == nil || *v.RelayOnly
}

// DERPServers 返回 address:port 指向内嵌 DERP 的服务器条目（保持配置顺序），它们
// 共同构成同一 region 的中继；没有任何 derp 标记时回退当前服务端（DefaultServer），
// 而不是 servers[0]——节点实际能连上的只有它此刻隧道所在的那台。
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

// DERPServer 返回多节点视图的第一个条目（单节点视图）。
func (c *ClientConfig) DERPServer() *ServerProfile {
	if servers := c.DERPServers(); len(servers) > 0 {
		return servers[0]
	}
	return nil
}

// VPNDERPAddrs 返回本节点地址里通告的全部 DERP host:port：按 CanonicalDERPAddr
// 规范化后去重并保持顺序。没有显式覆盖配置：地址必须与服务端对外地址逐字一致，
// 否则服务端认不出这条连接。
func (c *ClientConfig) VPNDERPAddrs() []string {
	var out []string
	seen := make(map[string]struct{})
	for _, srv := range c.DERPServers() {
		addr := srv.HostPort()
		if addr == "" {
			continue
		}
		canonical, err := config.CanonicalDERPAddr(addr)
		if err != nil {
			// 非法条目在这里不报错：严格校验在 vpn.BuildRegion 与 vpnnode.NewConfig，
			// 那里能带节点序号报上下文。
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
// （见 ValidateDERPServerAddr），调用方用 errors.Is 判定并告知用户。
var ErrCurrentServerNotDERPRelay = errors.New("vpn: the current server is not a usable DERP relay of this node")

// ValidateDERPServerAddr 校验 current（当前实际在运行的那台服务器）是本节点声明的
// DERP 中继之一：内嵌 DERP 只接待经其所属服务端隧道送达的连接，列表里没有它就永远
// 连不上。current 必须是显式入参——default 标记可能已指向别处。
func (c *ClientConfig) ValidateDERPServerAddr(current string) error {
	addrs := c.VPNDERPAddrs()
	if len(addrs) == 0 {
		return nil
	}
	if current == "" {
		return nil
	}
	canonicalCurrent, err := config.CanonicalDERPAddr(current)
	if err != nil {
		return fmt.Errorf("%w: cannot tell whether %q is one of them: %v",
			ErrCurrentServerNotDERPRelay, current, err)
	}
	parsed := 0
	for _, addr := range addrs {
		canonical, err := config.CanonicalDERPAddr(addr)
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

// ValidateDERPRelays 校验声明的内嵌 DERP 中继不超过 config.MaxVPNRelays：中继必须
// 全互联且整个集合内嵌在节点地址里，超限配置没有可工作的形态，因此在启动阶段拒绝
// （只在 vpn.enabled 时校验，按规范化后去重计数）。
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
		canonical, err := config.CanonicalDERPAddr(addr)
		if err != nil {
			continue
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		addrs = append(addrs, addr)
	}
	if len(addrs) <= config.MaxVPNRelays {
		return nil
	}
	return fmt.Errorf("servers[] has %d entries marked with \"derp\": true, which declare %d DERP relays (%s), "+
		"but at most %d relays are supported (1-2 are recommended): the relays of a region must be meshed with "+
		"one another and the whole set is embedded in this node's address, so delete the extra entries or remove "+
		"their \"derp\": true mark",
		marked, len(addrs), strings.Join(addrs, ", "), config.MaxVPNRelays)
}

// HostPort 返回一条 server 条目的对外 host:port：必须用 net.JoinHostPort 生成，
// 该值会被 SplitDERPAddr 拆进 DERPMap，IPv6 字面量需要方括号。
func (s *ServerProfile) HostPort() string {
	if s == nil || s.Host == "" {
		return ""
	}
	// applyDefaults 已经为 servers[].port 补过默认值，这里再兜一次是为了覆盖
	// 不经过它与 BuildSimpleConfig 的构造路径（移动端、测试）。
	port := s.Port
	if port <= 0 {
		port = config.DefaultServerPort
	}
	return net.JoinHostPort(s.Host, strconv.Itoa(port))
}

// VPNPeerPort 返回归一化后的 vpn.peer_port（见 config.NormalizeVPNPeerPort）：派生
// 放在访问器而不是 applyDefaults，否则 applyDefaults 早于 --local-port 覆盖会把派生
// 结果冻结在旧 socks_port 上。
func (c *ClientConfig) VPNPeerPort() int {
	return config.NormalizeVPNPeerPort(c.VPN.PeerPort, c.Local.SocksPort)
}
