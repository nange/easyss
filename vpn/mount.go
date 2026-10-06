package vpn

import (
	"net/http"
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

// NewDERPMount 返回 r 的顶层处理器：它把真正的 DERP 流量交给 derpH，其余一律
// 交给 fallback。
//
// 之所以要在 `/` 的兜底处理器内部按路径分流，而不是往 ServeMux 上多注册
// `/derp`、`/derp/probe` 等模式，是为了**伪装面**：derpserver.Handler 对不带
// Upgrade 头的请求会返回 426 与一行纯文本 "DERP requires connection upgrade"
// （derp/derpserver/handler.go:37-44）。那是一个一眼就能认出"这台机器跑 DERP"
// 的指纹。走这里之后，浏览器或扫描器访问 /derp 只会看到与其它未知路径完全一致
// 的伪装页面。
//
// 认账的条件只有两类：
//
//   - `Upgrade: derp`（或 websocket，Tailscale 的备用传输）：真实的 DERP 客户端；
//   - `/derp/probe` 与 `/derp/latency-check`：netcheck 的探测端点。它们是 DERP
//     家族的固定路径，返回体不含任何 DERP 字样，因此保留不会有指纹问题；反之
//     若把它们挡住，带 netcheck 的客户端会拿到伪装页而把中继判为不可用。
func NewDERPMount(derpH http.Handler, fallback Fallback) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isDERPRequest(r) {
			fallback.Serve(w, r)
			return
		}
		derpH.ServeHTTP(w, r)
	})
}

// isDERPRequest 报告一个请求是否属于 DERP 协议族。
func isDERPRequest(r *http.Request) bool {
	path := r.URL.Path
	if path != sharedconfig.DefaultVPNDERPPath && !strings.HasPrefix(path, sharedconfig.DefaultVPNDERPPath+"/") {
		return false
	}
	switch path {
	case sharedconfig.DefaultVPNDERPPath + "/probe", sharedconfig.DefaultVPNDERPPath + "/latency-check":
		return true
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
