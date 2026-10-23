package vpnnode

import (
	"context"
	"fmt"
	"time"

	tailcat "github.com/tailscale/tailcat"
)

// Path 是一条隧道的实际承载路径（见 PathStatus）。
type Path struct {
	// Direct 为 true 时这条路径是节点间直连（Endpoint 给出对端地址）；
	// 为 false 时经 DERP 中继（DERPRegionID/Code 给出是哪台中继）。
	Direct bool

	// Endpoint 是直连路径的对端地址（形如 ip:port），仅 Direct 时为非空。
	Endpoint string

	// DERPRegionID/DERPRegionCode 是承载该隧道的 DERP 中继，仅 !Direct 时有效。
	DERPRegionID   int
	DERPRegionCode string

	// Latency 是这次探测的往返时延。
	Latency time.Duration
}

// String 返回适合日志的一行描述。
func (p Path) String() string {
	if p.Direct {
		return "direct " + p.Endpoint
	}
	return fmt.Sprintf("via DERP(%s)", p.DERPRegionCode)
}

// PathStatus 用一次 disco ping 报告到对端的实际承载路径，用于确认
// `relay_only` 是否真的生效。
//
// 为什么不用 Client.Ping：它**总是**测量 DERP 路径（客户端上线前必然先经中继），
// 因此无论 relay_only 是什么都回报中继，证明不了任何事。DiscoPing 会主动触发
// 一次直连路径发现，于是"有没有直连"才成为一个可观测的事实——`relay_only=true`
// 时 magicsock 根本没有 UDP socket，直连不可能建立，Endpoint 必然为空。
//
// 它只做一次探测：直连路径发现在真实网络里可能需要若干次尝试（双方都要交换
// endpoint），因此 `Direct == false` 只说明"这次没走直连"；反过来 `Direct == true`
// 则是确凿的——那条路径真实可用。
func PathStatus(ctx context.Context, client *tailcat.Client) (Path, error) {
	res, err := client.DiscoPing(ctx)
	if err != nil {
		return Path{}, fmt.Errorf("vpn: probe the tunnel path: %w", err)
	}
	p := Path{
		Direct:         res.Endpoint != "",
		Endpoint:       res.Endpoint,
		DERPRegionID:   int(res.DERPRegionID),
		DERPRegionCode: res.DERPRegionCode,
		Latency:        time.Duration(res.LatencySeconds * float64(time.Second)),
	}
	if res.Err != "" {
		return p, fmt.Errorf("vpn: probe the tunnel path: %s", res.Err)
	}
	return p, nil
}
