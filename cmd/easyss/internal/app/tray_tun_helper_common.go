//go:build !headless

package app

import (
	"context"
	"fmt"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

// preResolveCore 是 preResolveHelperServer 唯一需要的核心能力，真实现是 runner.Core。
// 预解析是 TUN 系统 DNS 取值的唯一来源，"先作废、后预解析"的顺序是调用契约。
type preResolveCore interface {
	PrePopulateServerDomain(ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error
}

// preResolveHelperServer 在 helper 接管系统 DNS 之前填充服务端域名缓存，避免解析递归。
func preResolveHelperServer(core preResolveCore, cfg *clientconfig.ClientConfig) error {
	serverAddr := cfg.DefaultServer().Host
	if util.IsIP(serverAddr) {
		return nil
	}
	if len(clientconfig.DirectDNSServers) == 0 {
		return fmt.Errorf("failed to pre-resolve server hostname %s: dns cache not available", serverAddr)
	}

	// 上一次网络里"成功过"的解析器在当前网络可能不可达，而 PreferredSystemDNS 按首次成功
	// 顺序取值：不作废就会把死地址写进 TUN 的系统 DNS。必须紧接在下面这次预解析之前。
	dns.ResetResolveState()

	ctx, cancel := context.WithTimeout(context.Background(), dns.PreResolveTimeout)
	// 缓存由核心持有（runner.Core.PrePopulateServerDomain），是 DNS pinning 与 TUN 系统 DNS 的同一来源。
	err := core.PrePopulateServerDomain(ctx, serverAddr, clientconfig.DirectDNSServers,
		cfg.Routing.IPV6Rule != "enable")
	cancel()
	if err != nil {
		return fmt.Errorf("failed to pre-resolve server hostname %s: %w", serverAddr, err)
	}
	log.Info("[SYSTRAY] pre-populated dns cache for server", "host", serverAddr)
	return nil
}

// newHelperTunConfig 由与直连路径相同的设备快照构造 helper 配置。必须在预解析之后调用：
// PreferredSystemDNS 只反映本次网络验证过的解析器，先取值会把上一网络（或已熔断）的地址写进系统 DNS。
// MTU 与稍后交给 netstack 的值同源：helper 写进设备、主进程设 netstack，不一致时 netstack 会静默丢弃超限包。
func newHelperTunConfig(cfg *clientconfig.ClientConfig, dev tun.DeviceConfig) *proxy.TunConfig {
	return &proxy.TunConfig{
		Socks5Addr:     util.Socks5URI(cfg.Local.BindAll, cfg.Local.SocksPort),
		DNSAddr:        tunDNS(),
		Device:         dev.Device,
		TunIP:          dev.TunIP,
		TunGW:          dev.TunGW,
		TunMask:        dev.TunMask,
		TunIPV6Sub:     dev.TunIPV6Sub,
		TunGWV6:        dev.TunGWV6,
		ServerIPV6:     dev.ServerIPV6,
		LocalGateway:   dev.LocalGateway,
		LocalGatewayV6: dev.LocalGatewayV6,
		MTU:            cfg.TunMTU(),
	}
}
