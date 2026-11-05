package vpn

import (
	"errors"
	"fmt"

	"tailscale.com/tailcfg"

	"github.com/nange/easyss/v3/config"
)

// RegionID 是本内嵌 DERP 在自产 DERPMap 里的 region 编号：tailcat.Server.Start 把 0 当成
// "未设置"，因此必须为正；取值理由见 config.DefaultVPNRegionID。
const RegionID = config.DefaultVPNRegionID

// RegionCode / RegionName / DERPNodeName 只影响可读性，但保持稳定才能让跨节点日志对得上。
const (
	RegionCode   = "easyss"
	RegionName   = "easyss-embedded"
	DERPNodeName = "easyss-derp"
)

// BuildRegion 用对外通告的 host:port 列表构造自包含的 region：地址内嵌节点详情，客户端
// 无需查询 DERPMap，因此每个地址必须是节点能经自己隧道抵达的对外地址，顺序即 tailcat 的
// 尝试顺序。不设 STUNPort；背景与取舍见 docs/architecture.md 要点 19。
func BuildRegion(derpAddrs ...string) (*tailcfg.DERPRegion, error) {
	if len(derpAddrs) == 0 {
		return nil, errors.New("vpn: no DERP address to advertise; mark at least one servers[] entry with \"derp\": true")
	}
	seen := make(map[string]struct{}, len(derpAddrs))
	nodes := make([]*tailcfg.DERPNode, 0, len(derpAddrs))
	for i, addr := range derpAddrs {
		da, err := config.SplitDERPAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("DERP node %d: %w", i, err)
		}
		canonical, err := config.CanonicalDERPAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("DERP node %d: %w", i, err)
		}
		if _, dup := seen[canonical]; dup {
			return nil, fmt.Errorf("vpn: DERP node %s is declared twice; the same relay must not appear twice in one region", addr)
		}
		seen[canonical] = struct{}{}

		name := DERPNodeName
		if len(derpAddrs) > 1 {
			name = fmt.Sprintf("%s-%d", DERPNodeName, i+1)
		}
		nodes = append(nodes, &tailcfg.DERPNode{
			Name:     name,
			RegionID: RegionID,
			HostName: da.Host,
			DERPPort: da.Port,
		})
	}
	return &tailcfg.DERPRegion{
		RegionID:   RegionID,
		RegionCode: RegionCode,
		RegionName: RegionName,
		Nodes:      nodes,
	}, nil
}

// ValidateRegion 必须在构造期拒绝 RegionID 0：tailcat 编码地址时抹掉 region 编号、解析时
// 按序号补回，0 会产出看起来正常却与本机对不上的地址，真正的失败点偏远且不指向配置。
func ValidateRegion(region *tailcfg.DERPRegion) error {
	if region == nil {
		return errors.New("vpn: peer face requires a DERP region (the address must be self-contained)")
	}
	if region.RegionID == 0 {
		return errors.New("vpn: the DERP region has RegionID 0, which tailcat treats as unset; " +
			"build it with BuildRegion so the address really carries it")
	}
	if len(region.Nodes) == 0 {
		return errors.New("vpn: the DERP region has no nodes; the address would not be self-contained")
	}
	for i, n := range region.Nodes {
		if n == nil || n.HostName == "" {
			return fmt.Errorf("vpn: DERP region node %d has no host name; the address would not be self-contained", i)
		}
	}
	return nil
}
