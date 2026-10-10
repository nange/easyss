package vpnnode

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	tailcat "github.com/tailscale/tailcat"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// peerDERPAddrs 返回一个 tailcat 地址里内嵌的全部 DERP host:port。
//
// 地址自带 DERP 位置正是"零控制面"的来源，而 DERP 私有化要求双方通告同一组中继，
// 因此启动时要把这些内嵌位置读出来与本节点的比较（见 assertPeersShareDERPSet）。
// DERPPort 为 0 时按 derphttp 的行为取 443。
func peerDERPAddrs(addr string) ([]string, error) {
	ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		return nil, fmt.Errorf("invalid tailcat address: %w", err)
	}
	var out []string
	for ri, r := range ci.Region {
		for ni, n := range r.Nodes {
			if n == nil || n.HostName == "" {
				return nil, fmt.Errorf("tailcat address region %d node %d has no host name", ri, ni)
			}
			port := n.DERPPort
			if port == 0 {
				port = 443
			}
			out = append(out, net.JoinHostPort(n.HostName, strconv.Itoa(port)))
		}
	}
	return out, nil
}

// assertPeersShareDERPSet 断言每个对端通告的 DERP 节点集合与本节点相同（顺序无关）。
//
// 为什么必须是"集合相等"而不是"有交集"：内嵌 DERP 只接待经**本服务端**隧道送达的
// 连接（服务端把握手目标完全匹配到自己的 derp_addr 后改拨回环），所以节点实际能连上
// 的中继只能是它此刻隧道所落的那台服务端。于是"本节点能不能连上中继"取决于本节点
// 当前服务端是否在本节点集合里，"对端通过本节点地址能不能连上"取决于对端当前服务端
// 是否在本节点集合里。少一个节点就会让某一侧在耗尽列表后彻底连不上，多一个节点则
// 让对端先浪费一次尝试——两者都以"VPN 时好时坏"的形式出现，因此宁可启动即拒绝。
func assertPeersShareDERPSet(ownAddrs []string, peers []PeerRef) error {
	own, err := canonicalDERPSet(ownAddrs)
	if err != nil {
		return fmt.Errorf("vpn.derp_addr: %w", err)
	}
	ownText := strings.Join(ownAddrs, ", ")
	for i, p := range peers {
		addrs, err := peerDERPAddrs(p.Address)
		if err != nil {
			return fmt.Errorf("vpn.peers[%d] (%s): %w", i, p.HostName, err)
		}
		peer, err := canonicalDERPSet(addrs)
		if err != nil {
			return fmt.Errorf("vpn.peers[%d] (%s): %w", i, p.HostName, err)
		}
		missing, extra := diffDERPSets(own, peer)
		if len(missing) == 0 && len(extra) == 0 {
			continue
		}
		return fmt.Errorf("vpn.peers[%d] (%s) advertises DERP nodes (%s) while this node advertises (%s): "+
			"the embedded DERP is private and reachable only through each node's own easyss server, "+
			"so every node in a region must declare the same relay set; "+
			"not declared by this node: %s; not declared by the peer: %s; "+
			"mark the same servers[] entries with \"derp\": true on every node, then re-read each node's address with "+
			"\"easyss vpn identity\" and update the peers: the address is derived, not stored, so it changes on its own",
			i, p.HostName, strings.Join(addrs, ", "), ownText,
			strings.Join(extra, ", "), strings.Join(missing, ", "))
	}
	return nil
}

// canonicalDERPSet 把一组 host:port 规范化成"比较用"的集合（保持首次出现的顺序）：
// 同一个中继的不同书写（大小写、IPv6 括号形态）只算一个。
func canonicalDERPSet(addrs []string) ([]string, error) {
	out := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for i, addr := range addrs {
		canonical, err := sharedconfig.CanonicalDERPAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("node %d: %w", i, err)
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}

// diffDERPSets 返回 a 有而 b 没有的（missing）、以及 b 有而 a 没有的（extra）。
func diffDERPSets(a, b []string) (missing, extra []string) {
	inB := make(map[string]struct{}, len(b))
	for _, v := range b {
		inB[v] = struct{}{}
	}
	inA := make(map[string]struct{}, len(a))
	for _, v := range a {
		inA[v] = struct{}{}
	}
	for _, v := range a {
		if _, ok := inB[v]; !ok {
			missing = append(missing, v)
		}
	}
	for _, v := range b {
		if _, ok := inA[v]; !ok {
			extra = append(extra, v)
		}
	}
	return missing, extra
}

// AssertFullAddr 断言一个 tailcat 地址是**完整展开格式**，即它的 DERP region
// 详情已内嵌在地址里。这是本设计的硬契约。
//
// 反例是"短格式"：只携带一个 region ID 的地址。tailcat 解析它之后会去拉
// https://tailcat.dev/derpmap.json 才能知道该连哪台中继——那既依赖 Tailscale
// 官方的服务，也让"零控制面"不再成立。短格式一旦进入配置就会在最不方便的时刻
// （第一次访问对端时）才以网络错误的形式暴露，因此这里宁可当场拒绝。
//
// 除了 region 非空，还要求至少有一个带 HostName 的节点，以及地址里带有独立的
// disco 公钥：tailcat 客户端会拒绝缺少 disco 公钥的旧地址
// （tailcat.Client.initLocked），提前报错比在隧道启动时才失败清晰得多。
func AssertFullAddr(addr string) error {
	if addr == "" {
		return fmt.Errorf("tailcat address is empty")
	}
	ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		return fmt.Errorf("invalid tailcat address: %w", err)
	}
	if len(ci.Region) == 0 {
		return fmt.Errorf("tailcat address is not fully expanded: it carries only DERP region ID %d and would fetch %s; "+
			"copy the address printed by the peer's vpn startup log (or <exe>/vpn/peer.txt) instead",
			ci.RegionID, tailcat.DefaultDERPMapURL)
	}
	for ri, r := range ci.Region {
		if len(r.Nodes) == 0 {
			return fmt.Errorf("tailcat address region %d has no DERP nodes: the address is incomplete", ri)
		}
		for ni, n := range r.Nodes {
			if n.HostName == "" {
				return fmt.Errorf("tailcat address region %d node %d has no host name: the address is incomplete", ri, ni)
			}
		}
	}
	if ci.ServerDiscoPublic.IsZero() {
		return fmt.Errorf("tailcat address carries no disco public key; generate a new address with an up-to-date tailcat server")
	}
	return nil
}
