package vpnnode

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	tailcat "github.com/tailscale/tailcat"

	"github.com/nange/easyss/v3/config"
)

// peerDERPAddrs 返回一个 tailcat 地址里内嵌的全部 DERP host:port。
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
// 内嵌 DERP 只接待经本服务端隧道送达的连接，少一个中继就会让某一侧连不上，多一个
// 只会让对端先浪费一次尝试；差异因此必须作为启动错误暴露（见 docs/architecture.md 要点 19）。
func assertPeersShareDERPSet(ownAddrs []string, peers []PeerRef) error {
	own, err := canonicalDERPSet(ownAddrs)
	if err != nil {
		return fmt.Errorf("the DERP relay list this node advertises: %w", err)
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

// canonicalDERPSet 规范化 host:port 并去重：同一中继的不同书写（大小写、IPv6 括号）只算一个。
func canonicalDERPSet(addrs []string) ([]string, error) {
	out := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for i, addr := range addrs {
		canonical, err := config.CanonicalDERPAddr(addr)
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

// AssertFullAddr 断言一个 tailcat 地址是完整展开格式（DERP region 详情内嵌在地址里）。
// 短格式只带 region ID，解析时要去拉 tailcat.DefaultDERPMapURL，零控制面因此不成立；
// 缺 disco 公钥的地址会被 tailcat 客户端拒绝（Client.initLocked）。两者都必须当场报错。
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
