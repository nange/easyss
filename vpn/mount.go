package vpn

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/nange/easyss/v3/config"
)

// Fallback 与 server/handler.Fallback 的 Serve 方法对齐：vpn 是服务端与客户端共用的包，
// 不应反向依赖服务端 handler 的装配。
type Fallback interface {
	Serve(w http.ResponseWriter, r *http.Request)
}

// NewDERPMount 只把来自本机回环的 DERP 请求交给 derpH，其余一律走 fallback：节点经隧道连
// DERP，服务端认出目标是自己后改拨 127.0.0.1（见 server/handler 的 dialTarget），因此公网上
// 没有回答 DERP 协议的路径。分流必须留在 `/` 兜底处理器内部，未匹配请求才能逐字节一致。
func NewDERPMount(derpH http.Handler, fallback Fallback) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) || !isDERPRequest(r) {
			fallback.Serve(w, r)
			return
		}
		derpH.ServeHTTP(w, r)
	})
}

// isLoopbackRequest 报告请求是否来自本机回环：服务端自我拨号连 127.0.0.1，其它来源无论带
// 什么 Upgrade 头都只会看到伪装站点。
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		// 来源地址缺失或不可解析：按"不是回环"处理。
		return false
	}
	return addr.IsLoopback()
}

// isDERPRequest 只认 `Upgrade: derp|websocket` 与 netcheck 的 probe/latency-check 探测路径；
// 探测端点必须是 GET/HEAD，否则 derpserver 会回一行 "bogus probe method"（DERP 独有字节）。
// 其它 /derp 子树路径与未知 Upgrade 一律交给伪装页。
func isDERPRequest(r *http.Request) bool {
	path := r.URL.Path
	if path != config.DefaultVPNDERPPath && !strings.HasPrefix(path, config.DefaultVPNDERPPath+"/") {
		return false
	}
	switch path {
	case config.DefaultVPNDERPPath + "/probe", config.DefaultVPNDERPPath + "/latency-check":
		return r.Method == http.MethodGet || r.Method == http.MethodHead
	}
	if path != config.DefaultVPNDERPPath {
		// /derp 子树下的其它路径不存在，交给伪装页。
		return false
	}
	switch strings.ToLower(r.Header.Get("Upgrade")) {
	case "derp", "websocket":
		return true
	default:
		return false
	}
}
