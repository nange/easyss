package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
)

// 刻意吞掉写入错误：RST 只是发给一条可能已经死掉的流的最佳努力通知，失败无可补救。
func sendRST(s2c shaper.Shaper) {
	_ = s2c.PushFrame(protocol.NewFrameRST())
	_ = s2c.Flush()
}

// done 表示流已结束（FIN 或 RST），此时返回的帧就是终止帧。
func nextClientFrame(dr *crypto.DecryptedReader) (frame protocol.Frame, done bool, err error) {
	for {
		f, err := dr.ReadFrame()
		if err != nil {
			return protocol.Frame{}, false, err
		}
		switch f.Type {
		case protocol.FrameFIN, protocol.FrameRST:
			return f, true, nil
		case protocol.FramePADDING, protocol.FrameCOVER:
			continue
		default:
			return f, false, nil
		}
	}
}

// 标准库未导出这些 HTTP/2 流级错误与 RFC 9113 的连接拆除文本，只能匹配字符串。
var transientStreamPatterns = []string{
	"stream error: stream id ",
	"stream closed",
	"client disconnected",
	"client connection lost",
}

var errStreamIdleTimeout = errors.New("tcp stream idle timeout")

// 判定预期的拆除路径（对端离开该流、中继空闲超时），这类失败在客户端断开时会同时命中许多
// 流，只能记 Debug。刻意不判定 context.Canceled：net 拨号被取消时返回的错误也满足它。
func isTransientStreamError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, errClientGone) || errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, http.ErrBodyReadAfterClose) || errors.Is(err, errStreamIdleTimeout) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, pattern := range transientStreamPatterns {
		if strings.Contains(msg, pattern) {
			return true
		}
	}
	return false
}

// 也要接受裸 IP：IPConn 的 RemoteAddr 是不带端口的 *net.IPAddr，只用 net.SplitHostPort
// 会解析失败，SSRF 检查将永远不会触发。
func lanHostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	if host, _, ok := strings.CutLast(addr, "%"); ok {
		return host
	}
	return addr
}

// 拨号前的校验已在 candidates 里做完，这里兜住绕过 outbound 的拨号路径。
func rejectLANConn(conn net.Conn) error {
	if ra := conn.RemoteAddr(); ra != nil {
		if host := lanHostOf(ra.String()); util.IsLANIP(host) {
			_ = conn.Close()
			return fmt.Errorf("ssrf: rejected lan destination %s", host)
		}
	}
	return nil
}

// outboundDeps 是出站拨号的外部依赖：域名解析与单次尝试。指针在 handler、三个子
// dialer 与握手期 SSRF 校验之间共享，任何一处替换都会同时被所有读者看到。
type outboundDeps struct {
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	attempt func(d *net.Dialer, ctx context.Context, network, addr string) (net.Conn, error)
}

// 对应 net.Dialer 内部 partialDeadline 的 2s 下限，低于它就不值得再切分。
const defaultDialAttemptMinBudget = 2 * time.Second

func defaultOutboundDeps() *outboundDeps {
	// 一个 handler 一个缓存实例：握手期校验与拨号共用，同一主机的重复解析只付一次。
	cache := newResolveCache(util.ResolveHostIPs)
	return &outboundDeps{
		resolve: cache.lookup,
		attempt: func(d *net.Dialer, ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
	}
}

// 把客户端地址族与握手阶段校验过的目标地址从 ServeHTTP 传到拨号路径。
type dialCtxKey int

const (
	ctxPreferredFamily dialCtxKey = iota
	ctxResolvedAddrs
)

func withPreferredFamily(ctx context.Context, addr netip.Addr) context.Context {
	if !addr.IsValid() {
		return ctx
	}
	return context.WithValue(ctx, ctxPreferredFamily, addr)
}

func preferredFamily(ctx context.Context) (netip.Addr, bool) {
	addr, ok := ctx.Value(ctxPreferredFamily).(netip.Addr)
	return addr, ok && addr.IsValid()
}

// 拨号路径必须优先复用它们：一次流只解析一次，检查与连接才是同一批地址。
func withResolvedAddrs(ctx context.Context, addrs []netip.Addr) context.Context {
	if len(addrs) == 0 {
		return ctx
	}
	return context.WithValue(ctx, ctxResolvedAddrs, addrs)
}

func resolvedAddrs(ctx context.Context) ([]netip.Addr, bool) {
	addrs, ok := ctx.Value(ctxResolvedAddrs).([]netip.Addr)
	return addrs, ok && len(addrs) > 0
}

func clientPreferredFamily(remoteAddr string) netip.Addr {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// 首选族与另一族必须交错排列而不是整族分组：候选由 dialAddrs 串行尝试，整族排在前面时该族
// 第一个挂起的地址（被墙 IP 的 SYN 黑洞）会让另一族等完整族的预算。它只是偏好而非过滤。
func orderByFamily(addrs []netip.Addr, prefer netip.Addr) []netip.Addr {
	if !prefer.IsValid() || len(addrs) < 2 {
		return addrs
	}
	preferred := make([]netip.Addr, 0, len(addrs))
	rest := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Is4() == prefer.Is4() {
			preferred = append(preferred, addr)
			continue
		}
		rest = append(rest, addr)
	}
	ordered := make([]netip.Addr, 0, len(addrs))
	for i := range max(len(preferred), len(rest)) {
		if i < len(preferred) {
			ordered = append(ordered, preferred[i])
		}
		if i < len(rest) {
			ordered = append(ordered, rest[i])
		}
	}
	return ordered
}

// 优先复用握手阶段已解析并校验过的地址，没有时才自行解析。任一候选落在 LAN/私网/保留网段
// 即拒绝整个目标：校验与实际连接共用同一批地址，DNS-rebinding 因此没有翻转答案的窗口。
func (d *dialer) candidates(ctx context.Context, target string) ([]netip.Addr, error) {
	addrs, ok := resolvedAddrs(ctx)
	if !ok {
		var err error
		addrs, err = d.deps.resolve(ctx, target)
		if err != nil {
			return nil, err
		}
	}
	if lan := util.FirstLANAddr(addrs); lan.IsValid() {
		return nil, fmt.Errorf("ssrf: rejected lan destination %s (target %s)", lan, target)
	}
	prefer, _ := preferredFamily(ctx)
	return orderByFamily(addrs, prefer), nil
}

// 必须是显式错误而不是裸 context.Canceled：net 的取消错误也满足 Is(context.Canceled)，
// 客户端拆除与真正的拨号故障会混在一起。
var errClientGone = errors.New("client gone")

// 无端口的目标（ICMP）必须拨裸 IP，给原始套接字的目标带上端口会让 net.Dial 失败。
func dialAddr(addr netip.Addr, target string) string {
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return addr.String()
	}
	return net.JoinHostPort(addr.String(), port)
}

// 把剩余预算按剩余候选数均分，但不低于 minBudget：与 net.Dialer 内部 partialDeadline
// 同构，第一个候选挂起时最多吃掉一个子预算。
func attemptDeadline(now, deadline time.Time, candidatesLeft int, minBudget time.Duration) time.Time {
	left := deadline.Sub(now)
	if left <= 0 {
		return now
	}
	share := left / time.Duration(candidatesLeft)
	if share < minBudget {
		share = min(left, minBudget)
	}
	return now.Add(share)
}

// 整批候选共享一份 d.Timeout 预算（与把域名交给 net.Dialer 时一致）：每个候选各吃满一份会让
// N 个挂起的候选把一条流卡住 N×d.Timeout，且没有整体上界。
func (d *dialer) dialAddrs(ctx context.Context, nd *net.Dialer, network, target string, addrs []netip.Addr) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no candidate addresses to dial")
	}

	caller := ctx
	if nd.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, nd.Timeout)
		defer cancel()
	}

	var lastErr error
	for i, addr := range addrs {
		attemptCtx := ctx
		var cancel context.CancelFunc
		if deadline, ok := ctx.Deadline(); ok {
			attemptCtx, cancel = context.WithDeadline(ctx,
				attemptDeadline(time.Now(), deadline, len(addrs)-i, d.attemptMinBudget))
		}
		conn, err := d.deps.attempt(nd, attemptCtx, network, dialAddr(addr, target))
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return conn, nil
		}
		lastErr = err
		// 调用方离开优先于预算耗尽：前者要标成 errClientGone 让上层按预期的拆除处理。
		if caller.Err() != nil {
			return nil, fmt.Errorf("%w: %v", errClientGone, err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// 只拨校验过的字面地址，目标原文永远不传给拨号器，避免产生第二次未校验的解析。
func (d *dialer) outbound(ctx context.Context, nd *net.Dialer, network, target string) (net.Conn, error) {
	addrs, err := d.candidates(ctx, target)
	if err != nil {
		return nil, err
	}
	return d.dialAddrs(ctx, nd, network, target, addrs)
}

// keepAlive 为 0 表示系统默认（UDP/ICMP 没有长连接语义）。Timeout 必须显式设置：它既是
// dialAddrs 的总预算也是单次 DialContext 的上限，缺少它拨号会在 SYN 黑洞上挂到客户端放弃。
func outboundDialer(timeout, keepAlive time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
}

type dialer struct {
	nextProxy *nextproxy.NextProxy
	// 只要设置了 nextProxy 就必须同时设置它；ICMP 的原始 socket 无法由 SOCKS5 承载，
	// 两个都为空。
	shouldProxy func(target string) bool
	direct      func(ctx context.Context, network, target string) (net.Conn, error)
	deps        *outboundDeps
	// 每个候选至少拿到这么多预算，否则挂起的候选会让后面的候选只剩毫秒级窗口。
	attemptMinBudget time.Duration
}

func newDialer(np *nextproxy.NextProxy, shouldProxy func(target string) bool, deps *outboundDeps) dialer {
	return dialer{
		nextProxy:        np,
		shouldProxy:      shouldProxy,
		deps:             deps,
		attemptMinBudget: defaultDialAttemptMinBudget,
	}
}

// 入口日志与拨号路径共用它，日志里的路由才与实际拨号一致。
func (d *dialer) usesNextProxy(target string) bool {
	return d.nextProxy != nil && d.shouldProxy != nil && d.shouldProxy(target)
}

// 按目标决定路由；需要按域名决定路由的调用方（DNS 查询）改用 dialVia。
func (d *dialer) dialTarget(ctx context.Context, network, target string) (net.Conn, string, error) {
	return d.dialVia(ctx, network, target, "", d.usesNextProxy(target))
}

// 出站拨号的唯一实现，viaNextProxy 由调用方决定（按目标或按域名）；name 只用于日志。
func (d *dialer) dialVia(ctx context.Context, network, target, name string, viaNextProxy bool) (net.Conn, string, error) {
	if viaNextProxy && d.nextProxy != nil {
		// 有意保留「把域名交给上游代理解析」的语义：被墙或仅代理侧可解析的域名正是
		// next proxy 的用途，因此这里的检查只是尽力而为的早退，解析失败也放行。
		addrs, ok := resolvedAddrs(ctx)
		if !ok {
			var err error
			if addrs, err = d.deps.resolve(ctx, target); err != nil {
				log.Debug("[HANDLE] next proxy target resolve failed, handing the name to the proxy", "target", target, "err", err)
			}
		}
		if lan := util.FirstLANAddr(addrs); lan.IsValid() {
			return nil, "", fmt.Errorf("ssrf: rejected lan destination %s (target %s)", lan, target)
		}
		// 地址族刻意不下推到这一层：这里连的是上游 SOCKS5 代理而不是目标。
		attrs := []any{"target", target, "proxy", d.nextProxy.Host()}
		if name != "" {
			attrs = append(attrs, "name", name)
		}
		log.Debug("[HANDLE] dialing via next proxy", attrs...)
		conn, err := d.nextProxy.DialContext(ctx, network, target)
		if err != nil {
			return nil, "", err
		}
		return conn, d.nextProxy.Host(), nil
	}
	conn, err := d.direct(ctx, network, target)
	if err != nil {
		return nil, "", err
	}
	if err := rejectLANConn(conn); err != nil {
		return nil, "", err
	}
	return conn, remoteString(conn), nil
}
