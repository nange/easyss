package handler

import (
	"net"
	"net/http"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
)

// 三个会话 handler 各自持有其路由所用的代理，因此路由只有一个所有者；
// fallback 为 nil 时回落到包级内置实例，零值 ProxyHandler 也能服务回退页面。
type ProxyHandler struct {
	masterKey        []byte
	allowedMethods   map[protocol.Method]bool
	handshakeTimeout time.Duration
	shaperCfg        shaper.Config
	tcp              *tcpHandler
	udp              *udpHandler
	icmp             *icmpHandler
	saltCache        *saltCache
	ipLimiter        *ipRateLimiter
	fallback         *Fallback
	// deps 与三个子 handler 共用同一个实例：握手期 SSRF 校验与拨号必须是同一个解析器，
	// 否则构造后改一项就会让两者看到不同的答案。
	deps *outboundDeps
}

type ProxyHandlerConfig struct {
	MasterKey      []byte
	AllowedMethods []string
	// Timeouts 与 Shaper 都由调用方根据服务器配置构建好，本结构体不再重新派生或钳制。
	Timeouts  sharedconfig.Timeouts
	Shaper    shaper.Config
	NextProxy *nextproxy.NextProxy
	// HandshakeTimeout 覆盖等待 bootstrap 记录的超时。0 表示沿用 Timeouts.Base，这是服务器
	// 传入的值；测试可以缩小它而不影响派生的空闲超时。
	HandshakeTimeout time.Duration
	// Fallback 是服务非代理请求（伪装页面）的实例。nil 表示使用包级内置实例。
	Fallback *Fallback
}

// NewProxyHandler 组装代理 handler。未知的 AllowedMethods 被保留在 map 之外，由调用方在配置
// 加载阶段拒绝（见 server/config.validateAllowedMethods），这里不做"全部非法就放行"的兜底。
func NewProxyHandler(cfg ProxyHandlerConfig) *ProxyHandler {
	return newProxyHandlerWithDeps(cfg, defaultOutboundDeps())
}

func newProxyHandlerWithDeps(cfg ProxyHandlerConfig, deps *outboundDeps) *ProxyHandler {
	allowed := make(map[protocol.Method]bool)
	for _, m := range cfg.AllowedMethods {
		if method := protocol.MethodFromString(m); method != 0 {
			allowed[method] = true
		}
	}
	if len(allowed) == 0 && len(cfg.AllowedMethods) == 0 {
		allowed[protocol.MethodAES256GCM] = true
		allowed[protocol.MethodChaCha20Poly1305] = true
	}

	shaperCfg := cfg.Shaper.Normalize()
	// 零值填充只在这里发生一次（见 config.Timeouts.Normalize），三个子 handler
	// 都接收已归一化的集合，不再各自判断零值。
	timeouts := cfg.Timeouts.Normalize()

	// 一次握手等待占用两个 goroutine（handler 加首记录读取器），任何格式正确的 x-es
	// 头无需密码即可触发，超时过宽是廉价的 DoS 放大通道；0 表示沿用 Timeouts.Base。
	handshakeTimeout := cfg.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = timeouts.Base
	}
	handshakeTimeout = min(handshakeTimeout, maxHandshakeTimeout)

	return &ProxyHandler{
		masterKey:        cfg.MasterKey,
		allowedMethods:   allowed,
		handshakeTimeout: handshakeTimeout,
		shaperCfg:        shaperCfg,
		tcp:              newTCPHandler(timeouts, cfg.NextProxy, deps),
		udp:              newUDPHandler(timeouts, cfg.NextProxy, deps),
		icmp:             newICMPHandler(timeouts, deps),
		saltCache:        newSaltCache(),
		ipLimiter:        newIPRateLimiter(),
		fallback:         cfg.Fallback,
		deps:             deps,
	}
}

// fallbackFor 返回本 handler 使用的回退实例，未注入时回落到包级内置实例。
func (h *ProxyHandler) fallbackFor() *Fallback {
	if h.fallback != nil {
		return h.fallback
	}
	return builtinFallback()
}

// serveFallback 向响应写出一张伪装回退页面。
func (h *ProxyHandler) serveFallback(w http.ResponseWriter, r *http.Request) {
	h.fallbackFor().Serve(w, r)
}

// maxHandshakeTimeout 限制应答 408 之前等待第一个加密记录的时长（见 NewProxyHandler）。
const maxHandshakeTimeout = 8 * time.Second

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
