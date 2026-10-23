package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	serverconfig "github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/vpn"
)

// 本文件把 server.vpn.mesh_* 配置翻译成 vpn.Mesh 的输入：为每个对端准备一条经 easyss 隧道
// （本机指向该对端的 SOCKS5）的出网路径。代理不是可选优化而是唯一能成功的形态：内嵌 DERP
// 只接待回环来源，直连对端公网 host:port 只会拿到伪装页。

// meshDialersFor 为 cfg 里的每个 mesh 对端构造拨号器与（可选的）TLS 配置。
// shared 是按顶层 next_proxy 构造的实例（可能为 nil）：对端自带 proxy 时新建一个只用于 mesh 的
// NextProxy，否则复用它。
func meshDialersFor(cfg *serverconfig.FileConfig, shared *nextproxy.NextProxy, dialTimeout time.Duration) ([]vpn.MeshPeer, error) {
	peers := make([]vpn.MeshPeer, 0, len(cfg.Server.VPN.MeshPeers))
	for i, p := range cfg.Server.VPN.MeshPeers {
		np := shared
		if p.Proxy != "" {
			// enable_udp/all_host 对 mesh 无意义（只用 TCP CONNECT，不经过 ShouldProxy），固定为
			// false/true，与 handler 路径复用同一个构造入口。
			created, err := nextproxy.New(p.Proxy, false, true)
			if err != nil {
				return nil, fmt.Errorf("server.vpn.mesh_peers[%d] (%s): proxy: %w", i, p.Addr, err)
			}
			created.SetDialTimeout(dialTimeout)
			np = created
		}
		if np == nil {
			// 配置层已挡下；这里兜住绕过 LoadConfig 直接手搓 FileConfig 的调用方。
			return nil, fmt.Errorf("server.vpn.mesh_peers[%d] (%s) has no proxy and next_proxy.url is empty", i, p.Addr)
		}

		tlsConfig, err := meshTLSConfig(p)
		if err != nil {
			return nil, fmt.Errorf("server.vpn.mesh_peers[%d] (%s): %w", i, p.Addr, err)
		}
		peers = append(peers, vpn.MeshPeer{
			Addr:      p.Addr,
			Dial:      np.DialContext,
			TLSConfig: tlsConfig,
		})
	}
	return peers, nil
}

// meshTLSConfig 返回该对端的 TLS 配置：配了 ca_file 时用它作根证书，否则返回 nil 用系统根证书。
func meshTLSConfig(p serverconfig.MeshPeer) (*tls.Config, error) {
	if p.CAFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(p.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca_file %s contains no usable PEM certificate", p.CAFile)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// startDERPMesh 启动 mesh 客户端。它必须在 DERP 中继开始服务之前调用：derpserver
// 要求 SetMeshKey 早于服务（见 vpn.Mesh.Start）。
func (s *Server) startDERPMesh(cfg *serverconfig.FileConfig, derpSrv *vpn.DERPServer, shared *nextproxy.NextProxy, dialTimeout time.Duration) error {
	peers, err := meshDialersFor(cfg, shared, dialTimeout)
	if err != nil {
		return err
	}
	mesh, err := vpn.NewMesh(derpSrv, vpn.MeshOptions{
		MeshKey: cfg.Server.VPN.MeshKey,
		Peers:   peers,
	})
	if err != nil {
		return err
	}
	if err := mesh.Start(s.meshCtx); err != nil {
		return err
	}
	s.mesh = mesh

	addrs := make([]string, 0, len(cfg.Server.VPN.MeshPeers))
	for _, p := range cfg.Server.VPN.MeshPeers {
		addrs = append(addrs, p.Addr)
	}
	// 只打印对端与自己的中继公钥：mesh_key 是"被当成可信中继"的凭据，绝不进日志。
	log.Info("[SERVER] derp mesh enabled",
		"mesh_peers", addrs,
		"relay_key", derpSrv.PublicKey().ShortString(),
		"path", config.DefaultVPNDERPPath)
	return nil
}
