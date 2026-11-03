package handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

// 真实状态码只用于已有证据的失败：请求已被证明持有主密钥（端点/方法/目标不匹配），或是
// nginx 对同类请求同样会给出的应答（停滞的请求体 408、持续超限后的 429）。其余失败一律
// 返回伪装页，否则"同一请求第二次得到 400"本身就足以识别服务端实现。
func serveReject(w http.ResponseWriter, code int) {
	body := nginxErrorPage(code)
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	w.Write(body) //nolint:errcheck
}

// nginxErrorPage 复刻 nginx 默认错误页：空 body 加缺 Server 头是与任何 nginx 都不符的组合。
// 405/408 的状态行与 http.StatusText 不同，标题必须逐字一致。
func nginxErrorPage(code int) []byte {
	title := fmt.Sprintf("%d %s", code, http.StatusText(code))
	switch code {
	case http.StatusMethodNotAllowed:
		title = "405 Not Allowed"
	case http.StatusRequestTimeout:
		title = "408 Request Time-out"
	}
	var b strings.Builder
	b.WriteString("<html>\r\n<head><title>")
	b.WriteString(title)
	b.WriteString("</title></head>\r\n<body>\r\n<center><h1>")
	b.WriteString(title)
	b.WriteString("</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
	return []byte(b.String())
}

// x-es 头固定是 16 字节 salt 或能力令牌的 base64url（22 字符，与 crypto.saltSize 同源）。
// 头值来自对端：先按长度拒绝再解码，解码缓冲才不会随对端给出的长度增长。
const xesSaltB64Len = 22

var errXESHeader = errors.New("handler: malformed x-es header")

func decodeXES(s string) ([]byte, error) {
	if len(s) != xesSaltB64Len {
		return nil, errXESHeader
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errXESHeader
	}
	return b, nil
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

	salt, err := decodeXES(r.Header.Get("x-es"))
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

	endpoint := r.URL.Path
	sk, err := crypto.NewStreamKeys(h.masterKey, salt, endpoint)
	if err != nil {
		h.serveFallback(w, r)
		return handshakeResult{}, false
	}

	first, err := sk.ReadFirstRecordWithTimeout(r.Context(), r.Body, h.handshakeTimeout)
	if err != nil {
		stats.RecordServerHandshakeError()
		// 只有认证失败能证明对端在猜口令：超时与帧格式错误在没有密钥时同样会出现，
		// 拿它们做惩罚会把网络抖动也算成攻击。来源判定见 defaultPenaltyEligible。
		if peer := clientIP(r); errors.Is(err, crypto.ErrRecordAuthFailed) && h.shouldPenalize(peer) {
			h.ipLimiter.Penalize(peer)
		}
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

	// 首记录解出即证明持有主密钥，失败惩罚立即解除：用户改对口令后不该再等惩罚窗口。
	h.ipLimiter.RecordSuccess(clientIP(r))

	// 首个记录解出才证明持有主密钥：salt 必须记在这之后，否则停滞请求体留下的 408 会让同一
	// salt 的第二次请求变成回退页。任何 S2C 字节都在此之后写出，并发重放仍只有一个能过。
	if h.saltCache.MarkSeen(endpoint, salt) {
		log.Debug("[SERVER] replayed salt", "remote", r.RemoteAddr, "endpoint", endpoint)
		stats.RecordServerHandshakeError()
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
	if res.endpoint == config.EndpointTCP && h.tcp != nil && h.tcp.dial.usesNextProxy(res.target) {
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
	if res.endpoint == config.EndpointUDP {
		// 短窗口让数据报突发合并进单个加密记录，而不是每个数据报一个记录并强制 flush 一次。
		s2cCfg.BatchWindowMS = udpBatchWindowMS
	}
	s2cShaper := shaper.New(s2cWriter, s2cCfg)

	// 包成一次函数调用，这个 defer 才能既保证结果日志是该流的最后一个动作，又在 handler
	// panic 时（外层 recover 之前）照常收尾。
	func() {
		var handleResult streamResult
		defer func() { h.teardownSession(rc, s2cShaper, handleResult) }()

		// 出站优先用客户端接入所用的地址族，不依赖操作系统的双栈排序；客户端连接的族是这里
		// 唯一能观测到的信号。
		reqCtx := withResolvedAddrs(withPreferredFamily(r.Context(), clientPreferredFamily(r.RemoteAddr)), res.addrs)
		switch res.endpoint {
		case config.EndpointTCP:
			stats.RecordServerTCPStream()
			// cancelRead 立即解除阻塞在请求体上的读取 goroutine，而不是等 net/http 关闭。
			handleResult = h.tcp.Handle(reqCtx, c2sReader, s2cShaper, res.target, func() { _ = r.Body.Close() })
		case config.EndpointUDP:
			stats.RecordServerUDPStream()
			// 与 TCP 路径一致：否则帧读取器会停在请求体上，直到 ServeHTTP 返回后 net/http 关闭。
			handleResult = h.udp.Handle(reqCtx, c2sReader, s2cShaper, res.target, func() { _ = r.Body.Close() })
		case config.EndpointICMP:
			stats.RecordServerICMPStream()
			// ICMP 是一次性回显交换，没有 context 也没有 cancelRead，签名不对称是刻意的。
			handleResult = h.icmp.Handle(c2sReader, s2cShaper, res.target)
		}
		logHandlerResult(handleResult, res.target, res.endpoint, r.RemoteAddr)
	}()
}

// responseTeardownGrace 是响应收尾的预算。中继/会话结束后的 RST 与 shaper Close 都排在
// 可能卡住的响应写后面：WriteByteTimeout 只覆盖真正落到 socket 的写，覆盖不到 h2
// 流控等待，到点必须复位该流，handler goroutine 才不会跟着不读响应的客户端滞留。
const responseTeardownGrace = time.Second

// teardownSession 收尾一条流。预算内完成不设 deadline；超预算立即复位流，因此超预算时
// 仍在慢速推进的尾部同样会被截断。正常完成路径的数据已由处理循环冲刷，收尾通常只剩不足
// 一条记录的残余，拦住无限滞留优先。
func (h *ProxyHandler) teardownSession(rc *http.ResponseController, s2c shaper.Shaper, result streamResult) {
	// 收尾结束前必须等这个回调退出：它会在 handler 返回后触碰已经失效的 responseWriter。
	fired := make(chan struct{})
	timer := time.AfterFunc(h.teardownGrace, func() {
		defer close(fired)
		log.Debug("[SERVER] response teardown exceeded its budget, resetting the stream")
		_ = rc.SetWriteDeadline(time.Now())
	})

	if result.needsRST() {
		sendRST(s2c)
	}
	_ = s2c.Close()
	if !timer.Stop() {
		<-fired
	}
}
