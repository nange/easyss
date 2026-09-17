package handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"runtime/debug"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

// serveReject 为握手拒绝写出一个裸的 HTTP 错误响应。
// 与 ServeFallback 不同，它不发送伪装的 HTML 正文：它只用于被限流的请求、
// 等待握手记录超时的请求，或已经通过发送有效加密握手证明持有主密钥的请求——
// 对这些请求，4xx/5xx 状态码既真实可信，也能被 easyss 客户端区分，
// 客户端会在读取正文之前检查状态码。
func serveReject(w http.ResponseWriter, code int) {
	w.WriteHeader(code)
}

// handshakeResult 保存验证通过的握手结果，供 serveSession 使用。
type handshakeResult struct {
	sk       *crypto.StreamKeys
	first    crypto.FirstRecord
	endpoint string
	target   string
	method   protocol.Method
	// addrs 是握手阶段解析并校验过的目标地址（字面 IP 目标即该地址本身，
	// 解析失败时为空）。拨号路径复用它，因此一次流只解析一次，SSRF 检查与
	// 实际连接用的是同一批地址。
	addrs []netip.Addr
}

// ServeHTTP 处理一个请求：先在响应提交之前完成所有可能拒绝握手的前置检查
// （preflight），然后才是加密会话本身（serveSession）。
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if e := recover(); e != nil {
			log.Error("[SERVER] handler panic", "remote", r.RemoteAddr, "target", r.URL.Path, "panic", fmt.Sprint(e), "stack", string(debug.Stack()))
			_ = http.NewResponseController(w).Flush()
		}
	}()

	res, ok := h.preflight(w, r)
	if !ok {
		return
	}
	h.serveSession(w, r, res)
}

// preflight 在响应提交之前执行所有能用回退页面或裸 4xx/5xx 拒绝请求的检查
// （一旦 octet-stream 头被 flush，响应就无法再变成回退 HTML 页面）。
// ok=false 表示响应已经写出，ServeHTTP 必须返回。
func (h *ProxyHandler) preflight(w http.ResponseWriter, r *http.Request) (handshakeResult, bool) {
	if !r.ProtoAtLeast(2, 0) {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	// 代理端点只承载 POST 请求体（bootstrap 记录）。非 POST 请求
	// （GET/HEAD/OPTIONS 探测）不得进入握手路径：它们只会消耗 salt 缓存
	// 条目和限流预算，却不会产生任何结果。
	if r.Method != http.MethodPost {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	saltB64 := r.Header.Get("x-es")
	if saltB64 == "" {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	salt, err := base64.RawURLEncoding.DecodeString(saltB64)
	if err != nil || len(salt) != 16 {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	// 按源 IP 限制握手尝试，以缓解重放风暴和 CPU 滥用。只对看起来像真实
	// 握手的请求（带有有效的 x-es 头）计数，因此普通的回退页面流量不受影响。
	if !h.ipLimiter.Allow(clientIP(r)) {
		// 用 Debug 而非 Error：任何发送格式正确 x-es 头的对端都会走到这个
		// 分支，否则未经认证的轮换 IP 客户端可能刷爆日志。限流器在硬上限
		// 被触发时每个清理间隔只告警一次。
		log.Debug("[SERVER] handshake rate limited", "remote", r.RemoteAddr)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusTooManyRequests)
		return handshakeResult{}, false
	}

	// 拒绝重放的 bootstrap 记录。每个流使用唯一的随机 salt；该服务器已经
	// 接受过的 salt 意味着记录正在被重新投递（重放），接受它会导致重新拨号
	// 目标并重新投递第一个数据包。重放带有有效的加密握手，
	// 因此应答方已证明持有密钥，返回 400 是合适的。
	if h.saltCache.MarkSeen(r.URL.Path, saltB64) {
		log.Debug("[SERVER] replayed salt", "remote", r.RemoteAddr, "endpoint", r.URL.Path)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusBadRequest)
		return handshakeResult{}, false
	}

	endpoint := r.URL.Path
	sk, err := crypto.NewStreamKeys(h.masterKey, salt, endpoint)
	if err != nil {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	first, err := sk.ReadFirstRecordWithTimeout(r.Context(), r.Body, h.handshakeTimeout)
	if err != nil {
		stats.RecordServerHandshakeError()
		if errors.Is(err, crypto.ErrHandshakeTimeout) {
			log.Warn("[SERVER] read first record timed out", "remote", r.RemoteAddr, "endpoint", endpoint, "err", err)
			// 客户端已连接，但其 bootstrap 记录没有及时到达（链路拥塞、
			// 连接正在消亡）。真实的 HTTP/2 站点（nginx）会对迟到/缺失的
			// 请求体应答 408 Request Timeout；这里若返回伪装首页，会把 HTML
			// 混入合法客户端的记录流。408 让客户端快速干净地失败，
			// 而不是把页面误解析为记录。
			serveReject(w, http.StatusRequestTimeout)
			return handshakeResult{}, false
		}
		// 解密失败：请求没有证明持有主密钥（攻击者探测、密钥错误）。
		// 用 Debug 而非 Error：任何带有随机 x-es 头的请求都会走到这个分支，
		// 在这里做 error 级别日志会让未认证的对端刷爆日志。保持伪装首页，
		// 使服务器对无密钥请求与真实网站无法区分；easyss 客户端会在第一次
		// 会话读取时发现非加密载荷，并报告清晰的握手被拒绝错误。
		log.Debug("[SERVER] read first record failed", "remote", r.RemoteAddr, "endpoint", endpoint, "err", err)
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	if !first.Handshake.MatchesEndpoint(endpoint) {
		log.Error("[SERVER] endpoint mismatch", "remote", r.RemoteAddr, "proto", first.Handshake.Proto.String(), "endpoint", endpoint)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusNotFound)
		return handshakeResult{}, false
	}

	if !h.allowedMethods[first.Handshake.Method] {
		log.Error("[SERVER] method not allowed", "remote", r.RemoteAddr, "method", first.Handshake.Method.String())
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusMethodNotAllowed)
		return handshakeResult{}, false
	}

	target := first.Handshake.Target

	// 拒绝 LAN/私网目标以防止 SSRF 攻击。这必须在响应提交（WriteHeader +
	// Flush）之前完成：一旦 octet-stream 头被 flush，响应就无法再变成回退
	// HTML 页面，客户端会收到 200 application/octet-stream 而不是干净的拒绝。
	//
	// 这里解析出的地址会一路传给拨号路径（见 handshakeResult.addrs），拨号只
	// 拨这些校验过的字面地址，因此像 evil.com（检查时解析到公网、拨号时解析到
	// 127.0.0.1）这样的 DNS-rebinding 目标没有可翻转的第二次解析。
	//
	// 解析失败时不拒绝（沿用旧契约）：把 DNS 抖动变成 400 会误伤正常客户端，
	// 而拨号层会重新解析并再次校验，届时失败会以真实的拨号错误呈现。
	addrs, err := resolveHost(r.Context(), target)
	if err == nil {
		if lan := util.FirstLANAddr(addrs); lan.IsValid() {
			log.Error("[SERVER] rejected LAN target", "target", target, "resolved", lan, "remote", r.RemoteAddr)
			stats.RecordServerHandshakeError()
			serveReject(w, http.StatusBadRequest)
			return handshakeResult{}, false
		}
	} else {
		log.Debug("[SERVER] target resolve failed", "target", target, "remote", r.RemoteAddr, "err", err)
	}

	return handshakeResult{
		sk:       sk,
		first:    first,
		endpoint: endpoint,
		target:   target,
		method:   first.Handshake.Method,
		addrs:    addrs,
	}, true
}

// udpBatchWindowMS 是 UDP 会话专用的批处理窗口（毫秒）。它比配置的默认窗口短
// 得多：UDP 流是一串小的数据报，默认窗口会让每个数据报等待一次定时器才 flush，
// 而 1ms 足以把同一突发里的数据报合并进单个加密记录，同时不引入可感知的延迟。
const udpBatchWindowMS = 1

// serveSession 在响应上提交加密会话并分派给端点 handler。从第一次
// WriteHeader 开始的所有事情都发生在这里：响应已无法再变成回退 HTML 页面，
// 因此此后出现的失败表现为流级别的 RST 而不是 HTTP 错误。
func (h *ProxyHandler) serveSession(w http.ResponseWriter, r *http.Request, res handshakeResult) {
	log.Info("[SERVER] proxy", "target", res.target, "client", r.RemoteAddr)

	// 在提交响应之前预先创建并校验会话的 reader/writer。
	// 一旦调用 WriteHeader + Flush，响应就无法再变成回退 HTML 页面。
	// reader/writer 的创建会检查方法是否受支持（preflight 中已校验过），
	// 但这里还要防范意外的内部错误。请求已证明持有密钥，
	// 因此返回一个普通的 500（真实站点对内部故障的行为）是合适的。
	s2cWriter, err := res.sk.NewWriter(w, crypto.DirS2C, res.method)
	if err != nil {
		log.Error("[SERVER] s2c writer", "err", err)
		serveReject(w, http.StatusInternalServerError)
		return
	}
	c2sReader, err := res.sk.NewReader(r.Body, crypto.DirC2S, res.method)
	if err != nil {
		log.Error("[SERVER] c2s reader", "err", err)
		serveReject(w, http.StatusInternalServerError)
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	_ = rc.Flush()

	c2sReader.SetLeftoverFrames(res.first.Leftover)

	s2cCfg := h.shaperCfg
	if res.endpoint == sharedconfig.EndpointUDP {
		// UDP 使用较短的批处理窗口（udpBatchWindowMS），使数据报突发被合并进
		// 单个加密记录，而不是每个数据报一个记录并强制做一次 HTTP/2 flush。
		s2cCfg.BatchWindowMS = udpBatchWindowMS
	}
	s2cShaper := shaper.New(s2cWriter, s2cCfg)

	// 把 handler 分派包成一次函数调用，使下面这个 defer 既能在正常返回时
	// 保证"记录结果日志"是该流的最后一个动作，又能在 handler panic 时
	// （外层 recover 之前）照常关闭 shaper。
	func() {
		defer s2cShaper.Close() //nolint:errcheck

		var handleResult streamResult
		// 客户端到服务端的地址族决定出站拨号的优先地址族：客户端用 IPv4 接入时，
		// 服务端也优先用 IPv4 连目标，而不是依赖操作系统的双栈排序（后者在 VPS 上
		// 往往先试 IPv6）。客户端连接的族是这里唯一能观测到的信号。
		// 握手阶段解析并校验过的目标地址一并传入：拨号只拨它们，不再查 DNS。
		reqCtx := withResolvedAddrs(withPreferredFamily(r.Context(), clientPreferredFamily(r.RemoteAddr)), res.addrs)
		switch res.endpoint {
		case sharedconfig.EndpointTCP:
			stats.RecordServerTCPStream()
			// cancelRead 在中继终止（空闲超时/错误）时立即解除中继客户端读取
			// goroutine 的阻塞，而不是让它停留在请求体上直到 net/http 将其关闭。
			handleResult = h.tcp.Handle(reqCtx, c2sReader, s2cShaper, res.target, func() { _ = r.Body.Close() })
		case sharedconfig.EndpointUDP:
			stats.RecordServerUDPStream()
			// cancelRead 在 UDP handler 终止时立即解除客户端读取 goroutine 的阻塞，
			// 与 TCP 路径保持一致：否则帧读取器会停留在请求体上，
			// 直到 ServeHTTP 返回后 net/http 将其关闭。
			handleResult = h.udp.Handle(reqCtx, c2sReader, s2cShaper, res.target, func() { _ = r.Body.Close() })
		case sharedconfig.EndpointICMP:
			stats.RecordServerICMPStream()
			// ICMP 是"一次性回显交换"，没有 context 也没有 cancelRead，
			// 这处签名不对称是刻意的（见 icmpHandler.Handle）。
			handleResult = h.icmp.Handle(c2sReader, s2cShaper, res.target)
		}
		// 唯一的结果日志出口：一条流恰好在这里产生一条结果日志。
		logHandlerResult(handleResult, res.target, res.endpoint, r.RemoteAddr)
	}()
}
