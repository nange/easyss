package handler

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
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
	// teardownGrace 是响应收尾预算，默认 responseTeardownGrace；测试可以缩小它。
	teardownGrace time.Duration
	// deps 与三个子 handler 共用同一个实例：握手期 SSRF 校验与拨号必须是同一个解析器，
	// 否则构造后改一项就会让两者看到不同的答案。
	deps *outboundDeps
	// penaltyEligible 判断来源能否代表单个客户端；nil 视为不惩罚（零值 ProxyHandler 不崩）。
	penaltyEligible func(remoteAddr string) bool
	// disableFailurePenalty 关闭解密失败降速（server.disable_failure_penalty）。
	disableFailurePenalty bool
	// 惩罚期告警的限频状态，见 logPenaltyEntered。
	penaltyWarnMu       sync.Mutex
	lastPenaltyWarn     time.Time
	suppressedPenalties int
	// localDERP 在 match 或 loopback 为空时关闭该特例（两者都来自 ProxyHandlerConfig）。
	localDERP *localDERP
}

// localDERP 描述"握手目标就是本服务端自己的内嵌 DERP"这一特例：DERP 只接受回环来源
// （见 vpn.NewDERPMount），节点把 DERP 连接放进 easyss 隧道并以本服务端对外通告的地址为目标，
// 服务端必须认出来并改拨本机回环，否则那条连接会去连自己的公网入口（那里只有伪装页）。
type localDERP struct {
	// match 是本服务端对外通告的 DERP host:port（见 server/config.ResolveDERPAddr）。
	match string
	// loopback 是命中后实际拨号的地址：127.0.0.1:<listen 端口>。
	loopback string
}

// matches 忽略 host 大小写、按数值比较端口：一处写法差异就会变成"VPN 连不上"。
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
	// Timeouts 与 Shaper 都由调用方根据服务器配置构建好，本结构体不再重新派生或钳制。
	Timeouts  config.Timeouts
	Shaper    shaper.Config
	NextProxy *nextproxy.NextProxy
	// HandshakeTimeout 覆盖等待 bootstrap 记录的超时。0 表示沿用 Timeouts.Base，这是服务器
	// 传入的值；测试可以缩小它而不影响派生的空闲超时。
	HandshakeTimeout time.Duration
	// Fallback 是服务非代理请求（伪装页面）的实例。nil 表示使用包级内置实例。
	Fallback *Fallback
	// PenaltyEligible 覆盖"该来源能否代表单个客户端"的判定；nil 用 defaultPenaltyEligible。
	// 测试必须在 httptest 的回环来源上注入 true，否则覆盖不到惩罚路径。
	PenaltyEligible func(remoteAddr string) bool
	// DisableFailurePenalty 关闭解密失败的按 IP 降速。
	DisableFailurePenalty bool
	// LocalDERPAddr / LocalDERPLoopback 打开"目标是本服务端自己的内嵌 DERP"这一特例：
	// 前者是要匹配的对外 host:port，后者是命中后拨号的回环地址；任一为空即关闭。
	LocalDERPAddr     string
	LocalDERPLoopback string
}

// NewProxyHandler 组装代理 handler。未知的 AllowedMethods 被保留在 map 之外，由调用方在配置
// 加载阶段拒绝（见 server/config.validateAllowedMethods），这里不做"全部非法就放行"的兜底。
func NewProxyHandler(cfg ProxyHandlerConfig) *ProxyHandler {
	return newProxyHandlerWithDeps(cfg, newOutboundDeps(cfg.Timeouts))
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

	penaltyEligible := cfg.PenaltyEligible
	if penaltyEligible == nil {
		penaltyEligible = defaultPenaltyEligible
	}

	return &ProxyHandler{
		masterKey:             cfg.MasterKey,
		allowedMethods:        allowed,
		handshakeTimeout:      handshakeTimeout,
		shaperCfg:             shaperCfg,
		tcp:                   newTCPHandler(timeouts, cfg.NextProxy, deps),
		udp:                   newUDPHandler(timeouts, cfg.NextProxy, deps),
		icmp:                  newICMPHandler(timeouts, deps),
		saltCache:             newSaltCache(),
		ipLimiter:             newIPRateLimiter(),
		fallback:              cfg.Fallback,
		teardownGrace:         responseTeardownGrace,
		deps:                  deps,
		penaltyEligible:       penaltyEligible,
		disableFailurePenalty: cfg.DisableFailurePenalty,
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

// maxHandshakeTimeout 限制应答 408 之前等待第一个加密记录的时长（见 NewProxyHandler）。
const maxHandshakeTimeout = 8 * time.Second

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// defaultPenaltyEligible 只惩罚能代表单个客户端的公网来源：回环、私网与 CGNAT 后面
// 通常是同机反向代理、局域网或运营商 NAT，整片用户共用一个源 IP，按 IP 降速会放大成
// 整站不可用。CDN 回源地址是公网地址，这种部署用 server.disable_failure_penalty 关掉。
func defaultPenaltyEligible(remoteAddr string) bool {
	addr, err := netip.ParseAddr(remoteAddr)
	// 带 zone 的地址只可能是链路本地；util.IsLANIP 走 net.ParseIP，不认识 zone，
	// 直接交给它会把这个来源误判成公网。
	if err != nil || addr.Zone() != "" {
		return false
	}
	return !util.IsLANIP(remoteAddr)
}

// shouldPenalize 报告这次解密失败该不该记到来源 IP 上。零值 handler（penaltyEligible
// 为 nil）不惩罚，避免"没配置"变成 panic。
func (h *ProxyHandler) shouldPenalize(remoteAddr string) bool {
	if h.disableFailurePenalty || h.penaltyEligible == nil {
		return false
	}
	return h.penaltyEligible(remoteAddr)
}
