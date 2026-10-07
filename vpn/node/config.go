package vpnnode

import (
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/types/key"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// PeerRef 是一个对端节点在运行期的引用。
type PeerRef struct {
	// HostName 是应用里书写的名字（http://b:8080/、ssh user@b）。它只存在于
	// 访问侧本地，永远不会进入隧道。
	HostName string

	// Address 是对端的 tailcat 地址，完整展开格式（见 AssertFullAddr）。
	Address string

	// Port 是对端"对端面"在隧道内的端口。
	Port int
}

// Options 是构造 Config 的原始输入：字段可以留空表示"未配置"，由 NewConfig
// 填默认值并校验。它与 Config 分开，是为了让"未配置"与"显式配置为默认值"在
// 类型上仍然可区分，校验也只有一个入口。
type Options struct {
	// RelayOnly 强制全部经 DERP 中继、禁用节点间直连。
	RelayOnly bool

	// PeerPort 是本节点对端面在隧道内的端口，必须是已归一化的有效端口
	// （见 sharedconfig.NormalizeVPNPeerPort）。
	PeerPort int

	// OverlayCIDR 是访问侧本地的 overlay 段，留空取默认段
	// （见 sharedconfig.ParseVPNOverlayCIDR）。
	OverlayCIDR string

	// DERPAddr 是本节点在自己地址里通告的 DERP host:port。留空不可用：
	// 必须由调用方推导或显式给出（见 vpn.SplitDERPAddr）。
	DERPAddr string

	// Peers 是要访问的对端列表，可以为空（本节点只做被访问方）。
	Peers []PeerRef

	// AllowClients 是允许接入本节点对端面的对端 node key，文本格式
	// "nodekey:<hex>"（即 key.NodePublic.String() 的形态）。为空表示不限制。
	AllowClients []string
}

// Config 是 vpn 的运行期视图：每个字段都已经是归一化、校验过的有效值。
type Config struct {
	// RelayOnly 表示强制"只经服务端中继"。
	RelayOnly bool

	// PeerPort 是本节点对端面在隧道内的监听端口。
	PeerPort int

	// Overlay 是访问侧本地的 overlay 段，用来给对端分配虚拟 IPv4。
	Overlay netip.Prefix

	// DERPAddr 是本节点在自己地址里通告的 DERP host:port。
	DERPAddr string

	// Peers 是要访问的对端列表。
	Peers []PeerRef

	// AllowClients 是允许接入本节点对端面的对端 node key。
	AllowClients []key.NodePublic
}

// NewConfig 由原始输入构造运行期视图，并在这里集中完成 VPN 的全部校验。
//
// 校验集中在一处是有意的：这些错误都属于"配置写错了"，必须在启动阶段就以
// 明确的错误暴露出来，而不是等到第一次访问对端时以超时或握手失败的形式出现。
// 调用方（Core.StartVPN）拿到错误后应当让启动失败并原样打印。
func NewConfig(opts Options) (*Config, error) {
	if opts.PeerPort <= 0 || opts.PeerPort > 65535 {
		return nil, fmt.Errorf("invalid vpn.peer_port %d: must be in 1..65535", opts.PeerPort)
	}
	overlay, err := sharedconfig.ParseVPNOverlayCIDR(opts.OverlayCIDR)
	if err != nil {
		return nil, fmt.Errorf("vpn.overlay_cidr: %w", err)
	}
	if _, err := sharedconfig.SplitDERPAddr(opts.DERPAddr); err != nil {
		return nil, fmt.Errorf("vpn.derp_addr: %w", err)
	}
	peers, err := normalizePeers(opts.Peers)
	if err != nil {
		return nil, err
	}
	// DERP 私有化（见 docs/vpn-design.md 3.3）：节点的 DERP 连接只经 easyss
	// 隧道到达，由服务端把它映射到自己的回环监听。这条路径要求所有节点通告
	// 同一个 DERP host:port，否则访问对端时那台 DERP 根本不可达——而这会以
	// "隧道拨号超时"的形式出现在第一次访问对端时，所以在这里当场拒绝。
	if err := assertPeersShareDERP(opts.DERPAddr, peers); err != nil {
		return nil, err
	}
	allow, err := parseAllowedClients(opts.AllowClients)
	if err != nil {
		return nil, err
	}
	return &Config{
		RelayOnly:    opts.RelayOnly,
		PeerPort:     opts.PeerPort,
		Overlay:      overlay,
		DERPAddr:     opts.DERPAddr,
		Peers:        peers,
		AllowClients: allow,
	}, nil
}

// normalizePeers 校验并归一化对端列表。
//
// host_name 要求全局唯一（忽略大小写，因为 DNS 名字本身不区分大小写）且不能是
// IP 字面量：访问侧的查找顺序是"先按 host_name、再按 overlay IP"，一个看起来像
// IP 的名字会让这两条路径互相遮蔽，配置上应当直接拒绝。
//
// 写成 FQDN 的自然形态（"b."）在这里被归一化成 "b"：名字会被用在 URL、host:port
// 与 DNS 问题名三个地方，而只有 DNS 那一侧会自动去掉根点。不归一化的话，
// "b." 能通过校验却永远匹配不上（表现为对端神秘不可达）。
func normalizePeers(peers []PeerRef) ([]PeerRef, error) {
	out := make([]PeerRef, 0, len(peers))
	seen := make(map[string]string, len(peers))
	for i, p := range peers {
		name := trimDNSRoot(p.HostName)
		if name == "" {
			return nil, fmt.Errorf("vpn.peers[%d]: host_name is required", i)
		}
		if err := validateHostName(name); err != nil {
			return nil, fmt.Errorf("vpn.peers[%d]: %w", i, err)
		}
		lower := strings.ToLower(name)
		if prev, dup := seen[lower]; dup {
			return nil, fmt.Errorf("vpn.peers[%d]: host_name %q duplicates %q", i, name, prev)
		}
		seen[lower] = name

		if err := AssertFullAddr(p.Address); err != nil {
			return nil, fmt.Errorf("vpn.peers[%d] (%s): %w", i, name, err)
		}
		out = append(out, PeerRef{
			HostName: name,
			Address:  p.Address,
			// 与 peer_port 同样语义：未配置（以及越界）取默认值。
			Port: sharedconfig.NormalizeVPNPeerPort(p.Port, 0),
		})
	}
	return out, nil
}

// validateHostName 拒收那些注定匹配不上的 host_name。
//
// DNS 查询里的名字不区分大小写、也不含空白与冒号，而 host_name 会被直接用在
// URL 与其他 host:port 位置；因此含空白、冒号、斜杠的名字一定是配置错误。
func validateHostName(name string) error {
	if strings.ContainsAny(name, " \t\r\n/\\:@") {
		return fmt.Errorf("host_name %q contains an invalid character", name)
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("host_name %q is an IP literal; use a name (the overlay IP is assigned locally)", name)
	}
	return nil
}

// parseAllowedClients 把 "nodekey:<hex>" 文本解析为 node key，并去重。
func parseAllowedClients(list []string) ([]key.NodePublic, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]key.NodePublic, 0, len(list))
	seen := make(map[key.NodePublic]bool, len(list))
	for i, s := range list {
		var k key.NodePublic
		if err := k.UnmarshalText([]byte(s)); err != nil {
			return nil, fmt.Errorf("vpn.allow_clients[%d]: invalid node key %q: %w", i, s, err)
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out, nil
}
