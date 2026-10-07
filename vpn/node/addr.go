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
// 地址自带 DERP 位置正是"零控制面"的来源（见 docs/vpn-design.md 4.7），而 DERP
// 私有化要求所有节点通告同一台 DERP，因此启动时要把这些内嵌位置读出来与本节点的
// 比较（见 assertPeersShareDERP）。DERPPort 为 0 时按 derphttp 的行为取 443。
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

// assertPeersShareDERP 断言所有对端通告的 DERP 主机与本节点相同。
//
// DERP 私有化后，节点的 DERP 连接只经 easyss 隧道到达自己的服务端，并由服务端
// 映射到本机回环监听（见 docs/vpn-design.md 3.3）。这意味着"跨 S"拓扑不再成立：
// 对端通告的若是另一台 DERP 主机，访问该对端时的 DERP 连接会被送到本节点自己的
// 服务端，而它无法代表对方去连另一台机器。与其让它在第一次访问对端时表现成隧道
// 拨号超时，不如在启动时拒绝。
func assertPeersShareDERP(ownAddr string, peers []PeerRef) error {
	own, err := sharedconfig.SplitDERPAddr(ownAddr)
	if err != nil {
		return fmt.Errorf("vpn.derp_addr: %w", err)
	}
	ownText := net.JoinHostPort(own.Host, strconv.Itoa(own.Port))
	for i, p := range peers {
		addrs, err := peerDERPAddrs(p.Address)
		if err != nil {
			return fmt.Errorf("vpn.peers[%d] (%s): %w", i, p.HostName, err)
		}
		for _, a := range addrs {
			da, err := sharedconfig.SplitDERPAddr(a)
			if err != nil {
				return fmt.Errorf("vpn.peers[%d] (%s): %w", i, p.HostName, err)
			}
			if da.Port == own.Port && strings.EqualFold(da.Host, own.Host) {
				continue
			}
			return fmt.Errorf("vpn.peers[%d] (%s) advertises DERP %s while this node advertises %s: "+
				"the embedded DERP is private and reachable only through this node's own easyss server, "+
				"so every node must share one DERP host", i, p.HostName, a, ownText)
		}
	}
	return nil
}

// AssertFullAddr 断言一个 tailcat 地址是**完整展开格式**，即它的 DERP region
// 详情已内嵌在地址里。这是本设计的硬契约（见 docs/vpn-design.md 4.7）。
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
