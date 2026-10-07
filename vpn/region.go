package vpn

import (
	"errors"
	"fmt"

	"tailscale.com/tailcfg"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// RegionID 是本内嵌 DERP 在自产 DERPMap 里使用的 region 编号。
//
// tailcat.Server.Start 要求 region 的 RegionID 非零（零值会被当成"未设置"），
// 因此这个常量必须是正数；具体取值与理由见
// sharedconfig.DefaultVPNRegionID。
const RegionID = sharedconfig.DefaultVPNRegionID

// RegionCode / RegionName / DERPNodeName 是本内嵌 region 在日志、DERPMap 与
// 排障输出里的标识。它们只影响可读性，但保持稳定能让跨节点的日志对得上。
const (
	RegionCode   = "easyss"
	RegionName   = "easyss-embedded"
	DERPNodeName = "easyss-derp"
)

// 本文件不引入 tailcat：BuildRegion 只用到 tailcfg 与共享常量，而服务端的 DERP
// 中继只需要这些。任何 tailcat 引用都会把整个 WireGuard 引擎拖进服务端二进制
// （实测 +10 MiB），因此依赖 tailcat 的那部分（AssertFullAddr、节点身份）都在
// vpn/node 里。
//
// BuildRegion 由对外通告的 DERP host:port 构造一个自包含的 tailcat region，
// 供 tailcat.Server.Region 使用。
//
// 这里是"零控制面"的关键一环：把 DERP 的 host 与 port 内嵌进 region 之后，
// tailcat 生成的地址（ConnInfo.Addr）会带上完整的节点详情，拿到地址的客户端
// 无需查询任何 DERPMap。因此 derpAddr 必须是**客户端能直接连上**的 host:port，
// 即 easyss 服务端自己的对外地址，而不是它的监听地址（0.0.0.0:443 之类）。
//
// 节点不设 STUNPort：本设计只用 DERP 中继与 WireGuard 打洞，不需要 STUN
// 探测；tailcat 的 wire 编码也会丢弃 STUN-only 节点。
func BuildRegion(derpAddr string) (*tailcfg.DERPRegion, error) {
	da, err := sharedconfig.SplitDERPAddr(derpAddr)
	if err != nil {
		return nil, err
	}
	return &tailcfg.DERPRegion{
		RegionID:   RegionID,
		RegionCode: RegionCode,
		RegionName: RegionName,
		Nodes: []*tailcfg.DERPNode{{
			Name:     DERPNodeName,
			RegionID: RegionID,
			HostName: da.Host,
			DERPPort: da.Port,
		}},
	}, nil
}

// ValidateRegion 校验一个准备内嵌进地址的 region。
//
// RegionID 必须非零，而且这个检查必须发生在构造期：tailcat 在编码地址时会把 region
// 编号抹掉（省空间），解析时再按序号补回（第一个 region 补成 1）。于是一个
// RegionID 为 0 的 region 会产出一份"看起来完全正常、但与本机对不上"的地址，而
// 真正会失败的地方是 tailcat.Server.Start（"missing RegionID"），那里的错误信息
// 不会指向配置来源。见 tailcat 的 ConnInfo.Addr 与 ParseAddr。
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
