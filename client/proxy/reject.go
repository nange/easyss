package proxy

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/transport"
)

// HandshakeRejectKind 是客户端能从失败形状里区分出来的握手拒绝原因。服务端对未认证
// 请求只回伪装页或限流响应（响应必须不可区分，否则口令正确性可被探测），因此"口令
// 不匹配"只能由客户端推断。
type HandshakeRejectKind string

const (
	// RejectNotTunnel：服务端返回的是网页/非加密载荷。最常见的原因是客户端 password
	// 与服务端不一致，其次是 host/port 指到了别的站点。
	RejectNotTunnel HandshakeRejectKind = "not_tunnel"
	// RejectEndpointMismatch：服务端解密成功后仍不认识该端点（404）。对方是 Easyss 时
	// 说明口令是对的、版本/端点不一致；否则就是地址指错了站点。
	RejectEndpointMismatch HandshakeRejectKind = "endpoint_mismatch"
	// RejectMethodNotAllowed：解密成功但服务端不允许该加密方法（405）。
	RejectMethodNotAllowed HandshakeRejectKind = "method_not_allowed"
	// RejectRateLimited：握手被限流（429），反复用错口令也可能触发服务端惩罚。
	RejectRateLimited HandshakeRejectKind = "rate_limited"
	// 408/400/5xx 分别是服务端读首记录超时、拒绝请求与建立会话失败。408 与口令
	// 无关；400/5xx 需要看服务端配置与日志。
	RejectTimeout     HandshakeRejectKind = "timeout"
	RejectBadRequest  HandshakeRejectKind = "bad_request"
	RejectServerError HandshakeRejectKind = "server_error"
	// RejectOther：其余非 200 拒绝，只保留状态码事实。
	RejectOther HandshakeRejectKind = "rejected"
)

// logHint 是写给日志的可操作说明：让用户看到一行就够定位检查方向。
func (k HandshakeRejectKind) logHint() string {
	switch k {
	case RejectNotTunnel:
		return "server returned a web page instead of a tunnel stream; check that the client password matches the server, and that the address points at an Easyss server"
	case RejectEndpointMismatch:
		return "server does not serve this endpoint; if it is Easyss the password matched but versions/endpoints differ, otherwise the address points at another site"
	case RejectMethodNotAllowed:
		return "server rejected the cipher method; check server allowed_methods against the client method"
	case RejectRateLimited:
		return "handshake rate limited; repeated wrong passwords or a shared egress ip"
	case RejectTimeout:
		return "server timed out reading the first record; network or middlebox problem, not the password"
	case RejectBadRequest:
		return "server rejected the handshake request; check the server config and target"
	case RejectServerError:
		return "server failed to set up the session; see the server log"
	default:
		return "server rejected the handshake"
	}
}

// HandshakeReject 是一次被判定为配置类失败的握手拒绝，供日志与托盘归因。
type HandshakeReject struct {
	Kind   HandshakeRejectKind
	Target string
	Server string
	Err    error
}

// classifyHandshakeReject 只把"配置或地址错了"的失败归类为拒绝；网络错误、超时
// （context deadline）与流级错误必须原样放行，否则会把抖动当成配置问题。
func classifyHandshakeReject(err error) (HandshakeRejectKind, bool) {
	if err == nil {
		return "", false
	}
	if transport.IsServerAnsweredWithPage(err) || errors.Is(err, ErrServerRejectedHandshake) {
		return RejectNotTunnel, true
	}
	var rejected *transport.HandshakeRejectedError
	if !errors.As(err, &rejected) {
		return "", false
	}
	switch rejected.StatusCode {
	case http.StatusBadRequest:
		return RejectBadRequest, true
	case http.StatusNotFound:
		return RejectEndpointMismatch, true
	case http.StatusMethodNotAllowed:
		return RejectMethodNotAllowed, true
	case http.StatusRequestTimeout:
		return RejectTimeout, true
	case http.StatusTooManyRequests:
		return RejectRateLimited, true
	}
	if rejected.StatusCode >= 500 {
		return RejectServerError, true
	}
	return RejectOther, true
}

// rejectLogWindow 是同一原因重复告警的最小间隔。口令配错时每条新连接都会失败，逐条
// Warn 会淹没日志；窗口内只留一条，其余折叠成 suppressed 计数。
const rejectLogWindow = time.Minute

// handshakeRejector 把配置类握手失败折叠成限频日志，并只在"首次失败/恢复"两个状态
// 迁移上通知观察者，避免托盘被同一个错误反复打扰。零值可用。
type handshakeRejector struct {
	mu         sync.Mutex
	active     bool
	kind       HandshakeRejectKind
	lastLogged time.Time
	suppressed int
	onReject   func(HandshakeReject)
	onRecover  func()
	// now 只由测试替换，nil 表示 time.Now。
	now func() time.Time
}

// SetRejectObserver 注册配置类握手失败的观察者。onReject 只在失败状态从"无"变为
// "有"时调用一次；onRecovered 在任意一条流成功解密首帧后调用一次。两者都在流的
// goroutine 上执行，必须快速返回。
func (h *StreamHandler) SetRejectObserver(onReject func(HandshakeReject), onRecovered func()) {
	h.rejector.setObserver(onReject, onRecovered)
}

func (r *handshakeRejector) setObserver(onReject func(HandshakeReject), onRecovered func()) {
	r.mu.Lock()
	r.onReject, r.onRecover = onReject, onRecovered
	r.mu.Unlock()
}

// classify 是首读分类的唯一入口：成功解密一帧即证明口令匹配，据此解除告警。
func (r *handshakeRejector) classify(target, server string, err error) error {
	err = classifyFirstReadError(err)
	if err == nil {
		r.recovered()
		return nil
	}
	r.report(target, server, err)
	return err
}

// report 记录一次引导/首读失败。只有配置类失败才会产生日志与观察者回调。
func (r *handshakeRejector) report(target, server string, err error) {
	if r == nil {
		return
	}
	kind, ok := classifyHandshakeReject(err)
	if !ok {
		return
	}

	r.mu.Lock()
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	t := now()
	// 首次失败、原因变化或窗口已过都值得留一条 Warn；同一原因的窗口内重复只记 Debug。
	first := !r.active
	emit := first || r.kind != kind || t.Sub(r.lastLogged) >= rejectLogWindow
	suppressed := r.suppressed
	if emit {
		r.suppressed = 0
		r.lastLogged = t
	} else {
		r.suppressed++
	}
	r.active, r.kind = true, kind
	observer := r.onReject
	r.mu.Unlock()

	if !emit {
		log.Debug("[STREAM] handshake rejected (repeated)",
			"kind", kind, "target", target, "suppressed", suppressed)
		return
	}
	log.Warn("[STREAM] handshake rejected",
		"kind", kind, "hint", kind.logHint(), "target", target, "server", server,
		"suppressed", suppressed, "err", err)
	// 通知只挂在 episode 起点：窗口到期与原因变化仍要写日志，但同一次失败持续期间
	// 反复弹系统通知就变成骚扰了。
	if first && observer != nil {
		observer(HandshakeReject{Kind: kind, Target: target, Server: server, Err: err})
	}
}

// recovered 在任意一条流成功解密首帧后清除失败状态，并通知观察者一次。
func (r *handshakeRejector) recovered() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.active {
		r.mu.Unlock()
		return
	}
	r.active = false
	r.kind = ""
	r.suppressed = 0
	observer := r.onRecover
	r.mu.Unlock()

	log.Info("[STREAM] handshake recovered: server accepted the tunnel again")
	if observer != nil {
		observer()
	}
}

// serverAddr 为日志归因取所配置的服务端地址；传输层不提供时报空。
func (h *StreamHandler) serverAddr() string {
	if d, ok := h.transport.(transport.ServerAddrDescriber); ok {
		return d.ServerAddr()
	}
	return ""
}
