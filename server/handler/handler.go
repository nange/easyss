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

// ProxyHandler 持有三个按协议划分的会话 handler，但自身不保存任何
// next-proxy 状态：每个 handler 各自持有其路由所用的代理，因此路由只有一个
// 所有者，不会在它们之间漂移不一致。
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
}

type ProxyHandlerConfig struct {
	MasterKey      []byte
	AllowedMethods []string
	// Timeouts 保存全部已派生的时长（见 config.NewTimeouts），
	// Shaper 保存 shaper 设置（在此处归一化）。两者都由调用方根据服务器配置
	// 构建，因此本结构体不再重新派生或重新钳制任何值。
	Timeouts  sharedconfig.Timeouts
	Shaper    shaper.Config
	NextProxy *nextproxy.NextProxy
	// HandshakeTimeout 覆盖等待 bootstrap 记录的超时。0 表示使用
	// Timeouts.Base，这正是服务器传入的值；测试可以缩小它而不影响
	// 派生的空闲超时。
	HandshakeTimeout time.Duration
}

func NewProxyHandler(cfg ProxyHandlerConfig) *ProxyHandler {
	allowed := make(map[protocol.Method]bool)
	for _, m := range cfg.AllowedMethods {
		method := protocol.MethodFromString(m)
		if method != 0 {
			allowed[method] = true
		}
	}
	if len(allowed) == 0 {
		allowed[protocol.MethodAES256GCM] = true
		allowed[protocol.MethodChaCha20Poly1305] = true
	}

	shaperCfg := cfg.Shaper.Normalize()

	// 限制等待 bootstrap 记录的时间。整个等待期间一个握手请求会占用两个
	// goroutine（handler 加首记录读取器），而任何带有格式正确的 x-es 头的
	// 请求——无需密码——都能占用它们，因此过于宽松的超时是一个廉价的 DoS
	// 放大通道。合法客户端在打开流之后立即写入 bootstrap 记录，
	// 所以即使是高 RTT 链路也远低于此上限完成。
	handshakeTimeout := cfg.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = cfg.Timeouts.Base
	}
	if handshakeTimeout <= 0 {
		handshakeTimeout = maxHandshakeTimeout
	}
	if handshakeTimeout > maxHandshakeTimeout {
		handshakeTimeout = maxHandshakeTimeout
	}

	return &ProxyHandler{
		masterKey:        cfg.MasterKey,
		allowedMethods:   allowed,
		handshakeTimeout: handshakeTimeout,
		shaperCfg:        shaperCfg,
		tcp:              newTCPHandler(cfg.Timeouts.StreamIdle, cfg.Timeouts.Base, cfg.NextProxy),
		udp:              newUDPHandler(cfg.Timeouts.UDPIdle, cfg.Timeouts.Base, cfg.NextProxy),
		icmp:             newICMPHandler(cfg.Timeouts.Base),
		saltCache:        newSaltCache(),
		ipLimiter:        newIPRateLimiter(),
	}
}

// maxHandshakeTimeout 限制服务器在应答 408 之前等待流的第一个加密记录的时长
// （见 NewProxyHandler）。
const maxHandshakeTimeout = 8 * time.Second

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// remoteString 返回用于日志的可打印远端端点。它特意对 nil 安全：拨号得到的
// 连接可能报告未设置（nil）的 RemoteAddr，直接调用 RemoteAddr().String()
// 会 panic。next-proxy 路径不使用它（SOCKS5 连接报告的是代理的地址，
// 因此 dialTarget 改为记录配置的代理）。
func remoteString(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	if ra := conn.RemoteAddr(); ra != nil {
		return ra.String()
	}
	return ""
}
