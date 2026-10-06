package vpnnode

import (
	"fmt"

	tailcat "github.com/tailscale/tailcat"
)

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
