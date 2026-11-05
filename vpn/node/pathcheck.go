package vpnnode

import (
	"context"
	"fmt"
	"time"

	tailcat "github.com/tailscale/tailcat"
)

// Path 是一条隧道的实际承载路径（见 PathStatus）。
type Path struct {
	// Direct 为 true 时是节点间直连（Endpoint 给出对端地址），否则经 DERP 中继。
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

// PathStatus 用一次 disco ping 报告到对端的实际承载路径，用于确认 relay_only 生效。
// 不能用 Client.Ping：它总是测 DERP 路径。DiscoPing 会触发直连发现，relay_only=true
// 时没有 UDP socket，Endpoint 必然为空。只探测一次，Direct==false 只说明这次没走直连。
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
