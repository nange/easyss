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

// 这些请求已经证明持有主密钥（或被限流、等待握手记录超时），真实状态码才是可信的。
func serveReject(w http.ResponseWriter, code int) {
	w.WriteHeader(code)
}

type handshakeResult struct {
	sk       *crypto.StreamKeys
	first    crypto.FirstRecord
	endpoint string
	target   string
	method   protocol.Method
	// addrs 是握手阶段解析并校验过的目标地址（解析失败时为空）。拨号路径复用它，一次流
	// 因此只解析一次，SSRF 检查与实际连接用的是同一批地址。
	addrs []netip.Addr
}

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

// 必须在响应提交之前完成检查：octet-stream 头一旦 flush，响应就无法再变成回退 HTML 页面。
// ok=false 表示响应已经写出。
func (h *ProxyHandler) preflight(w http.ResponseWriter, r *http.Request) (handshakeResult, bool) {
	if !r.ProtoAtLeast(2, 0) {
		h.serveFallback(w, r)
		return handshakeResult{}, false
	}

	// 非 POST 请求（GET/HEAD/OPTIONS 探测）不得进入握手路径：它们只消耗 salt 缓存与限流预算。
	if r.Method != http.MethodPost {
		h.serveFallback(w, r)
		return handshakeResult{}, false
	}

	saltB64 := r.Header.Get("x-es")
	if saltB64 == "" {
		h.serveFallback(w, r)
		return handshakeResult{}, false
	}

	salt, err := base64.RawURLEncoding.DecodeString(saltB64)
	if err != nil || len(salt) != 16 {
		h.serveFallback(w, r)
		return handshakeResult{}, false
	}

	// 只对看起来像真实握手的请求（带有有效的 x-es 头）计数，普通回退页面流量不受影响。
	if !h.ipLimiter.Allow(clientIP(r)) {
		// 用 Debug 而非 Error：任何发送格式正确 x-es 头的对端都会走到这个分支，未经认证的
		// 轮换 IP 客户端能刷爆日志。
		log.Debug("[SERVER] handshake rate limited", "remote", r.RemoteAddr)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusTooManyRequests)
		return handshakeResult{}, false
	}

	// 见过的 salt 意味着记录正在被重放：接受它会重新拨号目标并重新投递第一个数据包。
	if h.saltCache.MarkSeen(r.URL.Path, saltB64) {
		log.Debug("[SERVER] replayed salt", "remote", r.RemoteAddr, "endpoint", r.URL.Path)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusBadRequest)
		return handshakeResult{}, false
	}

	endpoint := r.URL.Path
	sk, err := crypto.NewStreamKeys(h.masterKey, salt, endpoint)
	if err != nil {
		h.serveFallback(w, r)
		return handshakeResult{}, false
	}

	first, err := sk.ReadFirstRecordWithTimeout(r.Context(), r.Body, h.handshakeTimeout)
	if err != nil {
		stats.RecordServerHandshakeError()
		if errors.Is(err, crypto.ErrHandshakeTimeout) {
			log.Warn("[SERVER] read first record timed out", "remote", r.RemoteAddr, "endpoint", endpoint, "err", err)
			// 这里若返回伪装首页，会把 HTML 混入合法客户端的记录流，客户端会把它误解析为记录。
			serveReject(w, http.StatusRequestTimeout)
			return handshakeResult{}, false
		}
		// 用 Debug 而非 Error：任何带随机 x-es 头的请求都会走到这里。保持伪装首页，服务器对
		// 无密钥请求才与真实网站无法区分。
		log.Debug("[SERVER] read first record failed", "remote", r.RemoteAddr, "endpoint", endpoint, "err", err)
		h.serveFallback(w, r)
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

	// 拒绝 LAN/私网目标以防 SSRF，且必须在响应提交之前完成。解析出的地址一路传给拨号路径，拨号
	// 只拨这些字面地址，DNS-rebinding 没有可翻转的第二次解析。解析失败不拒绝，拨号层会重新解析校验。
	addrs, err := h.deps.resolve(r.Context(), target)
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

// 比配置的默认窗口短得多：UDP 是一串小数据报，1ms 足以合并同一突发且不引入可感知的延迟。
const udpBatchWindowMS = 1

// 与拨号路径共用 dialer.usesNextProxy，避免日志说直连、实际却走了代理。结果日志成功时是
// Debug，因此这条 Info 是成功流唯一能看到路由的出口。
func (h *ProxyHandler) sessionLogAttrs(res handshakeResult, client string) []any {
	attrs := []any{"target", res.target, "client", client}
	if res.endpoint == sharedconfig.EndpointTCP && h.tcp != nil && h.tcp.dial.usesNextProxy(res.target) {
		attrs = append(attrs, "via_next_proxy", true, "proxy", h.tcp.dial.nextProxy.Host())
	}
	return attrs
}

// 从第一次 WriteHeader 起响应已无法再变成回退 HTML 页面，此后出现的失败表现为流级别的
// RST 而不是 HTTP 错误。
func (h *ProxyHandler) serveSession(w http.ResponseWriter, r *http.Request, res handshakeResult) {
	// 每条流只有这一条入口日志与 logHandlerResult 一条结果日志，handler 内部不再打印
	// 拨号/连接/失败步骤。
	log.Info("[SERVER] proxy", h.sessionLogAttrs(res, r.RemoteAddr)...)

	// 必须在 WriteHeader + Flush 之前创建并校验 reader/writer，之后响应就无法再变成回退
	// HTML 页面。
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
		// 短窗口让数据报突发合并进单个加密记录，而不是每个数据报一个记录并强制 flush 一次。
		s2cCfg.BatchWindowMS = udpBatchWindowMS
	}
	s2cShaper := shaper.New(s2cWriter, s2cCfg)

	// 包成一次函数调用，这个 defer 才能既保证结果日志是该流的最后一个动作，又在 handler
	// panic 时（外层 recover 之前）照常关闭 shaper。
	func() {
		defer s2cShaper.Close() //nolint:errcheck

		var handleResult streamResult
		// 出站优先用客户端接入所用的地址族，不依赖操作系统的双栈排序；客户端连接的族是这里
		// 唯一能观测到的信号。
		reqCtx := withResolvedAddrs(withPreferredFamily(r.Context(), clientPreferredFamily(r.RemoteAddr)), res.addrs)
		switch res.endpoint {
		case sharedconfig.EndpointTCP:
			stats.RecordServerTCPStream()
			// cancelRead 立即解除阻塞在请求体上的读取 goroutine，而不是等 net/http 关闭。
			handleResult = h.tcp.Handle(reqCtx, c2sReader, s2cShaper, res.target, func() { _ = r.Body.Close() })
		case sharedconfig.EndpointUDP:
			stats.RecordServerUDPStream()
			// 与 TCP 路径一致：否则帧读取器会停在请求体上，直到 ServeHTTP 返回后 net/http 关闭。
			handleResult = h.udp.Handle(reqCtx, c2sReader, s2cShaper, res.target, func() { _ = r.Body.Close() })
		case sharedconfig.EndpointICMP:
			stats.RecordServerICMPStream()
			// ICMP 是一次性回显交换，没有 context 也没有 cancelRead，签名不对称是刻意的。
			handleResult = h.icmp.Handle(c2sReader, s2cShaper, res.target)
		}
		logHandlerResult(handleResult, res.target, res.endpoint, r.RemoteAddr)
	}()
}
