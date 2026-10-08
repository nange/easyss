package handler

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
)

// ProxyHandler 持有三个按协议划分的会话 handler，但自身不保存任何
// next-proxy 状态：每个 handler 各自持有其路由所用的代理，因此路由只有一个
// 所有者，不会在它们之间漂移不一致。
//
// fallback 由 server 启动路径构造并注入（见 handler.NewFallback）；为 nil 时
// 回落到包级内置实例，使零值 ProxyHandler 也能服务回退页面。
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
	localDERP        *localDERP
}

// localDERP 描述"握手目标就是本服务端自己的内嵌 DERP"这一特例。
//
// DERP 只接受回环来源（见 vpn.NewDERPMount），节点侧则把 DERP 连接放进 easyss
// 隧道并原样使用配置里的 vpn.derp_addr 作为目标（见 runner/derpshim.go）。因此
// 服务端必须在这里把它认出来，并改拨本机回环监听——否则那条连接会去解析并连接
// 自己的公网地址，而公网入口只提供伪装页面。
type localDERP struct {
	// match 是本服务端对外通告的 DERP host:port（server.vpn.derp_addr，或由
	// domain/listen 推导）。为空表示本服务端没有内嵌 DERP。
	match string
	// loopback 是命中后实际拨号的地址：127.0.0.1:<listen 端口>。
	loopback string
}

// matches 报告握手目标是否就是本服务端自己的 DERP 地址。
//
// host 忽略大小写（DNS 名字不区分大小写，而配置里的大小写由运维书写），端口按
// 数值比较（"443" 与 "0443" 等价，避免一处写法差异变成"VPN 连不上"）。
func (l *localDERP) matches(target string) bool {
	if l == nil || l.match == "" || l.loopback == "" {
		return false
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	matchHost, matchPort, err := net.SplitHostPort(l.match)
	if err != nil {
		return false
	}
	targetPort, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	wantPort, err := strconv.Atoi(matchPort)
	if err != nil {
		return false
	}
	return targetPort == wantPort && strings.EqualFold(host, matchHost)
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
	// Fallback 是服务非代理请求（伪装页面）的实例。nil 表示使用包级内置实例。
	Fallback *Fallback
	// LocalDERPAddr / LocalDERPLoopback 打开"目标是本服务端自己的内嵌 DERP"
	// 这一特例：前者是要匹配的对外 host:port，后者是命中后拨号的回环地址。
	// 两者任一为空即关闭该特例。
	LocalDERPAddr     string
	LocalDERPLoopback string
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
		fallback:         cfg.Fallback,
		localDERP: &localDERP{
			match:    cfg.LocalDERPAddr,
			loopback: cfg.LocalDERPLoopback,
		},
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
