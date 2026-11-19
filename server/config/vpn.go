package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/nange/easyss/v3/config"
)

// VPNConfig 恰好持有服务端配置文件 "server.vpn" 键下的全部字段。
// 地址与挂载路径都不可配：对外 host:port 只由 server.domain 与 listen 端口推导（ResolveDERPAddr），
// 路径固定 /derp（客户端 derphttp 与 derpserver 都硬编码，单一来源 config.DefaultVPNDERPPath）。
type VPNConfig struct {
	// Enabled 表示在本服务端的 HTTPS 监听上挂载内嵌 DERP 中继。
	Enabled bool `json:"enabled"`

	// MeshKey 是同一 region 内所有中继共享的预共享密钥（config.ParseVPNMeshKey：64 位 hex 原样，
	// 其余非空字符串按 SHA-256 派生），对端凭它信任本中继的订阅与代转发。无 omitempty 是为了让
	// 示例配置列出该字段。
	MeshKey string `json:"mesh_key"`

	// MeshPeers 是本中继要互联的**其他**中继：Addr 必须等于对端自己的 DERP 对外地址（服务端靠
	// 完全匹配认出这条连接），且必须经 easyss SOCKS5 进隧道。mesh 全互联，所以本机 + 这里的条数
	// 是 region 的中继总数，上限 config.MaxVPNRelays，超限由 validateVPNMesh 拒绝启动。
	MeshPeers []MeshPeer `json:"mesh_peers"`

	// DERPSendQueueDepth 是本中继为**每个**客户端缓存的待发帧数，也是这条路径上唯一能存住未确认数据
	// 的地方：单流吞吐 ≈ 深度 × 每帧约 1.4KB / RTT。0 或负值取 config.DefaultDERPSendQueueDepth 后钳制，
	// 默认值与钳制只在 NormalizeDERPSendQueueDepth 定义一次；进程环境里的同名变量只是实现细节，无 omitempty 只为示例配置列出它。
	DERPSendQueueDepth int `json:"derp_send_queue_depth"`
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

// ResolveDERPAddr 返回本服务端对外通告的 DERP host:port：host 取 server.domain、port 取 server.listen
// 的端口（DERP 就挂在这个 HTTPS 监听上，节点把同一个地址内嵌进节点地址）。任何与推导结果不同的写法都会
// 让 localDERP 的完全匹配失效，因此没有覆盖项；推不出端口时返回错误，不退回任何猜测值。
func (fc *FileConfig) ResolveDERPAddr() (string, error) {
	if fc.Server.Host == "" {
		return "", fmt.Errorf("cannot derive the DERP address: server.host is empty")
	}
	port := fc.Server.Port
	if port == 0 {
		port = config.DefaultServerPort
	}
	return net.JoinHostPort(fc.Server.Host, strconv.Itoa(port)), nil
}

// validateVPN 固定 VPN 的启动期契约，由 LoadConfig 调用：这些错误必须在进程启动时以配置错误暴露。
// 只在 vpn.enabled 时校验——未启用的 VPN 配置不参与运行期，不应阻止服务端启动。
func (fc *FileConfig) validateVPN() error {
	vpnCfg := fc.Server.VPN

	// 配了 mesh 但没开 VPN 时中继根本没挂载，必须报错而不是静默忽略。
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

// validateVPNMesh 的规则都是"配了也连不上"的硬前提：每个对端必须经代理（内嵌 DERP 只服务回环），
// 且本机 + peers 就是 region 的中继总数（每个节点地址里内嵌的是整组中继）。
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
	// region 规模是 len(mesh_peers)+1（mesh 是全互联），不是"每台中继各自连了几台"。
	if total := len(vpnCfg.MeshPeers) + 1; total > config.MaxVPNRelays {
		return fmt.Errorf("server.vpn.mesh_peers lists %d peer relays, so this region would have %d relays in total: "+
			"a mesh may contain at most %d relays (1-2 are recommended), because every relay has to be meshed "+
			"with all the others and every node embeds the whole set in its address",
			len(vpnCfg.MeshPeers), total, config.MaxVPNRelays)
	}
	if _, err := config.ParseVPNMeshKey(vpnCfg.MeshKey); err != nil {
		return fmt.Errorf("server.vpn.mesh_key: %w", err)
	}

	own, err := fc.ResolveDERPAddr()
	if err != nil {
		return err
	}
	ownCanonical, err := config.CanonicalDERPAddr(own)
	if err != nil {
		return err
	}

	seen := make(map[string]int, len(vpnCfg.MeshPeers))
	for i, peer := range vpnCfg.MeshPeers {
		canonical, err := config.CanonicalDERPAddr(peer.Addr)
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

// validateMeshProxy 与 nextproxy.New 保持同一条契约（只支持 socks5），放在配置加载阶段是为了启动即失败。
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
