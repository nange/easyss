package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// VPNConfig 恰好持有服务端配置文件 "server.vpn" 键下的全部字段。
//
// 服务端在 VPN 组网里有三个角色：内嵌 DERP 中继、本机自己的 DERP 地址、以及
// （可选的）同 region 内与其他中继之间的 mesh。它没有、也不需要 tailcat 客户端侧
// 的 peers[]（那是节点配置的事）。
//
// 这里刻意没有 derp_addr：DERP 的对外地址只有一个来源——server.domain 与
// server.listen 的端口（见 ResolveDERPAddr）。内嵌 DERP 是私有端点，节点只经
// easyss 隧道抵达，而服务端靠"握手目标完全匹配这个地址"把它认出来并改拨回环
// （见 handler.ProxyHandlerConfig.LocalDERPAddr），所以它必须与每个节点
// servers[] 里那条被标记 derp 的条目逐字一致。做成配置项只会提供一个
// "服务端以为自己叫什么、节点却写在别处"的失配开关——那种失配的症状是 VPN
// 一直连不上，而不是一条配置错误。端口转发/反向代理这类"对外 host:port 与监听
// 不同"的形态因此明确不支持：DERP 就挂在 server.listen 这个监听上。
//
// 同理没有 derp_path：DERP 的挂载路径不可配。客户端侧
// derphttp.Client.urlString 把路径硬编码为 /derp
// （tailscale.com/derp/derphttp/derphttp_client.go:293），derpserver.Handler 也
// 文档化要求"mounted at /derp"并在内部分流绝对路径 /derp/probe 与
// /derp/latency-check（derp/derpserver/handler.go:28）。因此把它做成配置项只会
// 提供一个一改就让所有节点连不上的开关；单一事实来源是
// sharedconfig.DefaultVPNDERPPath。
type VPNConfig struct {
	// Enabled 表示在本服务端的 HTTPS 监听上挂载内嵌 DERP 中继。
	Enabled bool `json:"enabled"`

	// MeshKey 是同一 region 内所有中继共享的预共享密钥（见
	// sharedconfig.ParseVPNMeshKey：64 位 hex 原样使用，其余非空字符串按
	// SHA-256 派生）。它把本中继与其他中继连接起来：对端凭它识别"这是可信的
	// mesh 同伴"，从而允许订阅连接变化并代其他客户端转发数据包。
	//
	// 没有 omitempty 是有意的：示例配置（-show-config-example）要列出这个字段，
	// 否则"新增字段静默漏在示例之外"。
	MeshKey string `json:"mesh_key"`

	// MeshPeers 是本中继要与之互联的**其他**中继。每条的 Addr 必须等于对端
	// 自己的 DERP 对外地址（由对方的 domain 与 listen 端口推导，服务端靠完全
	// 匹配认出"这条连接是来访问我的 DERP 的"），并且必须经一个 easyss 客户端
	// （通常是 easyss-headless）的 SOCKS5 送进隧道——内嵌 DERP 只接待回环来源，
	// 直连公网端口只会看到伪装页。
	MeshPeers []MeshPeer `json:"mesh_peers"`
}

// MeshPeer 是 mesh 里的一个对端中继。
type MeshPeer struct {
	// Addr 是对端自己的 DERP 对外地址（host:port，即对端的 domain 与 listen
	// 端口）。
	Addr string `json:"addr"`

	// Proxy 是把该对端的连接送进隧道的 SOCKS5 代理，通常是本机上指向该对端的
	// easyss-headless 的 socks 端口。留空表示用顶层的 next_proxy.url。
	Proxy string `json:"proxy,omitempty"`

	// CAFile 是对端使用私有/自签证书时的根证书文件。留空表示用系统根证书
	// （certmagic 的 Let's Encrypt 证书就是这种情形）。
	CAFile string `json:"ca_file,omitempty"`
}

// ResolveDERPAddr 返回本服务端对外通告的 DERP host:port。
//
// 服务端没有 servers[]，地址因此只有一个来源：host 取 server.domain，port 取
// server.listen 的端口——DERP 就挂在这个 HTTPS 监听上，客户端会用同一个
// host:port 建立 HTTP/1.1 Upgrade 连接，并把它内嵌进自己的节点地址。刻意没有
// "显式覆盖"的配置项：任何与这个推导结果不同的写法（端口转发、反向代理）都会
// 让服务端的 localDERP 完全匹配失效，节点拿到的中继地址也就永远连不上。
//
// 推导不出端口时（例如 listen 只写了主机名）一律返回错误，由调用方让启动失败，
// **不退回任何猜测值**：一个猜错的中继地址会让每个节点都连不上，而错误信息能
// 直接指出缺的是 domain 还是端口。
func (fc *FileConfig) ResolveDERPAddr() (string, error) {
	if fc.Server.Domain == "" {
		return "", fmt.Errorf("cannot derive the DERP address: server.domain is empty")
	}
	port, err := sharedconfig.PortFromListen(fc.Server.Listen)
	if err != nil {
		return "", fmt.Errorf("cannot derive the DERP port from server.listen: %w", err)
	}
	return net.JoinHostPort(fc.Server.Domain, strconv.Itoa(port)), nil
}

// validateVPN 固定 VPN 的启动期契约，由 LoadConfig 在配置加载阶段调用，使这些
// 错误在进程启动时（而不是第一次有节点来连时）以明确的配置错误暴露出来。
//
// 只在 vpn.enabled 时校验：未启用的 VPN 配置不参与运行期，不应阻止服务端启动。
func (fc *FileConfig) validateVPN() error {
	vpnCfg := fc.Server.VPN

	// mesh 配置只在 VPN 启用时才有意义：一份"配了 mesh 但没开 VPN"的配置会让
	// 运维以为中继在互联，实际上连中继本身都没挂载。
	if !vpnCfg.Enabled {
		if vpnCfg.MeshKey != "" || len(vpnCfg.MeshPeers) > 0 {
			return fmt.Errorf("server.vpn.mesh_key/mesh_peers are set while server.vpn.enabled is false: " +
				"the embedded DERP relay is not mounted, so there is nothing to mesh with")
		}
		return nil
	}
	if _, err := fc.ResolveDERPAddr(); err != nil {
		return err
	}
	return fc.validateVPNMesh()
}

// validateVPNMesh 校验 server.vpn 的 mesh 部分。规则与理由：
//
//   - mesh_key 与 mesh_peers 必须同时给出：只有一边时既可能是漏配（中继不会互联，
//     跨节点的客户端收不到对方的数据包），也可能是误解（以为密钥本身就能发现对端）；
//   - 每个对端要么自带 proxy，要么全局配了 next_proxy.url：DERP 只在回环上被服务，
//     直连对端的公网 host:port 只会拿到伪装页，因此"没有代理"不是一种可工作的配置；
//   - 对端地址不能是本服务端自己的 DERP 对外地址（自连没有意义，而且 mesh 协议会把它
//     当成自连后放弃），也不能重复。
func (fc *FileConfig) validateVPNMesh() error {
	vpnCfg := fc.Server.VPN
	switch {
	case vpnCfg.MeshKey == "" && len(vpnCfg.MeshPeers) == 0:
		return nil
	case vpnCfg.MeshKey == "":
		return fmt.Errorf("server.vpn.mesh_peers is set without server.vpn.mesh_key: " +
			"the mesh key is what lets a peer relay trust this one for connection watching and packet forwarding")
	case len(vpnCfg.MeshPeers) == 0:
		return fmt.Errorf("server.vpn.mesh_key is set without server.vpn.mesh_peers: " +
			"add every other relay of this region (its own DERP address, i.e. its domain and listen port) to mesh_peers")
	}
	if _, err := sharedconfig.ParseVPNMeshKey(vpnCfg.MeshKey); err != nil {
		return fmt.Errorf("server.vpn.mesh_key: %w", err)
	}

	own, err := fc.ResolveDERPAddr()
	if err != nil {
		return err
	}
	ownCanonical, err := sharedconfig.CanonicalDERPAddr(own)
	if err != nil {
		return err
	}

	seen := make(map[string]int, len(vpnCfg.MeshPeers))
	for i, peer := range vpnCfg.MeshPeers {
		canonical, err := sharedconfig.CanonicalDERPAddr(peer.Addr)
		if err != nil {
			return fmt.Errorf("server.vpn.mesh_peers[%d].addr: %w", i, err)
		}
		if canonical == ownCanonical {
			return fmt.Errorf("server.vpn.mesh_peers[%d].addr is this server's own DERP address (%s): "+
				"mesh_peers lists the *other* relays of the region", i, own)
		}
		if prev, dup := seen[canonical]; dup {
			return fmt.Errorf("server.vpn.mesh_peers[%d].addr duplicates mesh_peers[%d] (%s)", i, prev, peer.Addr)
		}
		seen[canonical] = i

		if peer.Proxy == "" {
			if fc.NextProxy.URL == "" {
				return fmt.Errorf("server.vpn.mesh_peers[%d] (%s) has no proxy and next_proxy.url is empty: "+
					"the embedded DERP only accepts connections that arrive through an easyss tunnel, "+
					"so give this peer a socks5:// proxy (e.g. the local easyss-headless) or set next_proxy.url", i, peer.Addr)
			}
			continue
		}
		if err := validateMeshProxy(peer.Proxy); err != nil {
			return fmt.Errorf("server.vpn.mesh_peers[%d].proxy: %w", i, err)
		}
	}
	return nil
}

// validateMeshProxy 校验 mesh 对端的代理 URL。与 nextproxy.New 保持同一条契约
// （只支持 socks5），但在这里报错以便配置加载阶段就失败。
func validateMeshProxy(proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", proxyURL, err)
	}
	if u.Scheme != "socks5" {
		return fmt.Errorf("unsupported scheme %q in %q: only socks5 is supported", u.Scheme, proxyURL)
	}
	if u.Host == "" {
		return fmt.Errorf("missing host in %q", proxyURL)
	}
	return nil
}
