package vpn

import (
	"net/http"

	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"
)

// DERPServer 是本进程内嵌的 DERP 中继。
//
// 它只做中继：客户端与对端各自与自己 tailcat 服务端之间建立 WireGuard 会话，
// 打洞失败时数据经这里转发。因为中继与代理服务端在同一个进程/同一个 HTTPS
// 监听上，节点之间"打不通就走服务端"不需要任何额外部署。
//
// 刻意不启用 client 校验（SetVerifyClient 默认为 false，且我们不会去改它）：
// 那套校验依赖本机运行 tailscaled 的 LocalAPI，与"不依赖 Tailscale 官方组件"
// 的目标冲突。接入控制由 tailcat 地址里的 preshared key 与可选的对端面白名单
// （vpn.allow_clients）负责。
type DERPServer struct {
	srv     *derpserver.Server
	handler http.Handler
}

// NewDERPServer 用持久化的 DERP 私钥构造内嵌 DERP 服务端。
//
// 私钥必须持久化：DERP 公钥会写在握手响应里（Derp-Public-Key），换钥匙会让
// 已在线的节点需要重连，也让排障时的日志对不上。
func NewDERPServer(privateKey key.NodePrivate) *DERPServer {
	srv := derpserver.New(privateKey, Logf)
	return &DERPServer{
		srv:     srv,
		handler: derpserver.Handler(srv),
	}
}

// Handler 返回应挂在 config.DefaultVPNDERPPath 下的处理器。
func (d *DERPServer) Handler() http.Handler {
	return d.handler
}

// PublicKey 返回 DERP 中继的公钥（排障与日志用）。
func (d *DERPServer) PublicKey() key.NodePublic {
	return d.srv.PublicKey()
}

// Close 关闭中继并断开所有已连接的客户端。
func (d *DERPServer) Close() error {
	if d == nil || d.srv == nil {
		return nil
	}
	return d.srv.Close()
}
