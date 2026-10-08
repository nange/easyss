package vpn

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// Fallback 是伪装页面的最小接口，与 server/handler.Fallback 的 Serve 方法对齐。
//
// 用接口而不是直接依赖 *handler.Fallback：vpn 是服务端与客户端共用的包，不应
// 反向依赖服务端的 handler 装配；同时它让 mount 的路由契约可以脱离真实伪装页
// 单独测试。
type Fallback interface {
	Serve(w http.ResponseWriter, r *http.Request)
}

// NewDERPMount 返回 r 的顶层处理器：只有**来自本机回环**的 DERP 流量才交给
// derpH，其余一律交给 fallback。
//
// 为什么 DERP 只接受回环来源：节点不直连服务端的
// /derp，而是把 DERP 连接放进 easyss 隧道（客户端把 tailscale 的出站接进本地
// 入口，见 runner/derpshim.go），服务端在握手阶段认出"目标就是我自己的 DERP
// 地址"后改拨 127.0.0.1:<listen>（见 server/handler 的 dialTarget）。于是：
//
//   - 内嵌 DERP 不再是公网上的匿名中继：拿到域名的人无法直接用它中转，接入
//     控制由 easyss 协议（master key）承担；
//   - 公网上没有任何"回答 DERP 协议"的路径，扫描器看到的始终是伪装站点——
//     包括 POST /derp/probe 这类探测（derpserver 对非 GET 会回一行独有文案）。
//
// 在 `/` 的兜底处理器内部按来源与路径分流（而不是往 ServeMux 上多注册
// `/derp`），是为了让"非 DERP 请求"与其它未知路径的响应逐字节一致。
func NewDERPMount(derpH http.Handler, fallback Fallback) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) || !isDERPRequest(r) {
			fallback.Serve(w, r)
			return
		}
		derpH.ServeHTTP(w, r)
	})
}

// isLoopbackRequest 报告请求是否来自本机回环地址。
//
// 服务端的自我拨号（见 server/handler 的 dialTarget）连的是 127.0.0.1，因此
// 来源必然是回环。任何来自其它地址的请求——无论带不带 DERP 的 Upgrade 头——
// 都只会看到伪装站点。
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		// 来源地址缺失或不可解析（例如手工构造的请求）：按"不是回环"处理。
		return false
	}
	return addr.IsLoopback()
}

// isDERPRequest 报告一个请求是否属于 DERP 协议族。
//
// 认账的条件只有两类：
//
//   - `Upgrade: derp`（或 websocket，Tailscale 的备用传输）：真实的 DERP 客户端；
//   - `/derp/probe` 与 `/derp/latency-check`：netcheck 的探测端点。它们是 DERP
//     家族的固定路径，返回体不含任何 DERP 字样，因此保留不会有指纹问题；反之
//     若把它们挡住，带 netcheck 的客户端会拿到伪装页而把中继判为不可用。它们
//     只认 GET/HEAD——derpserver 的 ProbeHandler 对其它方法会回一行
//     "bogus probe method"（derp/derpserver/handler.go），那是一个本函数存在的
//     意义所在：不让任何非 DERP 客户端看到 DERP 独有的字节。
func isDERPRequest(r *http.Request) bool {
	path := r.URL.Path
	if path != sharedconfig.DefaultVPNDERPPath && !strings.HasPrefix(path, sharedconfig.DefaultVPNDERPPath+"/") {
		return false
	}
	switch path {
	case sharedconfig.DefaultVPNDERPPath + "/probe", sharedconfig.DefaultVPNDERPPath + "/latency-check":
		return r.Method == http.MethodGet || r.Method == http.MethodHead
	}
	if path != sharedconfig.DefaultVPNDERPPath {
		// /derp 子树下的其它路径不存在，交给伪装页——真实 DERP 服务端也只有
		// 这三个路径，多出来的路径只会暴露实现细节。
		return false
	}
	switch strings.ToLower(r.Header.Get("Upgrade")) {
	case "derp", "websocket":
		return true
	default:
		return false
	}
}
