package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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

// sendRST 通过 s2c shaper 推送一个 RST 帧并 flush：这是所有 handler
// 在响应提交后向客户端告知其流失败的统一方式。
func sendRST(s2c shaper.Shaper) {
	_ = s2c.PushFrame(protocol.NewFrameRST())
	_ = s2c.Flush()
}

// nextClientFrame 从客户端流中读取下一个可处理的帧，跳过 PADDING/COVER。
// done 表示流已结束（FIN 或 RST），此时返回的帧就是终止帧。err 会中止一切。
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

// transientStreamPatterns 列出表示"对端已离开该流"的错误片段（全部小写）。
// 客户端正常拆除（关闭本地连接 → RST_STREAM(CANCEL) → 服务端读请求体失败）
// 会让每个流都产生一条这样的错误，因此它们不能按故障记录。每条都是完整短语
// 而不是裸 "canceled"/"closed"，这样目标侧的真错误（拨号被拒、目标重置、
// 解密失败）不会被误降级。
var transientStreamPatterns = []string{
	// HTTP/2 流/连接级取消：标准库用未导出的哨兵包装，只能靠字符串匹配。
	"stream error: stream id ",
	"stream closed",
	"client connection lost",
	// net/http：请求体在我们自己关闭（中继终止）之后仍被读取。
	"invalid read on closed body",
	// 传输层断开。
	"connection reset by peer",
	"broken pipe",
	"connection was aborted",
	// relay：正常的流生命周期结束。
	"idle timeout",
	"stream drained",
	// http2: Transport 在收到 GOAWAY 之后新建流失败。
	"http2: no cached connection was available",
	"use of closed network connection",
}

// isTransientStreamError 报告流失败是否是预期的拆除路径（对端取消/重置了该流、
// 传输层断开、中继空闲超时），而不是真正的故障。这类失败在客户端断开或回收
// 连接时会同时命中许多流，应以 Debug 级别记录，而不是逐流刷满 Info/Error。
//
// 这里刻意不判定 context.Canceled：net 在拨号被取消时返回的取消错误
// （"operation was canceled"）满足 errors.Is(err, context.Canceled)，直接按它
// 归类会把真正的拨号故障一起静音。只有我们自己的 errClientGone 才代表客户端离开。
func isTransientStreamError(err error) bool {
	if err == nil {
		return false
	}
	// net.ErrClosed 同时覆盖 net.Conn 与 net/http 的请求体
	// （http.ErrBodyReadAfterClose 就是用 net.ErrClosed 包装的）；
	// io.ErrClosedPipe 来自我们主动关闭的流，同样属于拆除路径。
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, errClientGone) || errors.Is(err, os.ErrDeadlineExceeded) {
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

// lanHostOf 提取远端地址的主机部分，支持 "host:port"（TCPAddr/UDPAddr）
// 或裸 IP 形式（IPConn）。IPConn 的 RemoteAddr 是 *net.IPAddr，
// 其 String() 不带端口——链路本地 IPv6 可能带也可能不带 %zone 后缀——
// 因此仅靠 net.SplitHostPort 对它必然失败，SSRF 检查将永远不会触发。
func lanHostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	if i := strings.LastIndexByte(addr, '%'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// rejectLANConn 当 conn 的远端地址是 LAN/私网 IP 时关闭它并返回拒绝错误。
// 它是 TCP/UDP/ICMP handler 共享的拨号后 SSRF 防护：握手阶段已校验目标，
// 但拨号会重新解析域名目标，因此 DNS 重绑定（DNS-rebinding）的域名在这里
// 可能解析到 LAN 主机。在发送任何数据之前拒绝该连接。
func rejectLANConn(conn net.Conn) error {
	if ra := conn.RemoteAddr(); ra != nil {
		if host := lanHostOf(ra.String()); util.IsLANIP(host) {
			_ = conn.Close()
			return fmt.Errorf("ssrf: rejected lan destination %s", host)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 出站地址族对齐
// ---------------------------------------------------------------------------

// lookupIPAddr 解析域名的全部地址。测试通过替换它注入确定性的解析结果，
// 使拨号候选的排序不依赖真实 DNS。
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

// dialCtxKey 是未导出的 context 键类型，用于把"客户端到服务端的地址族"
// 从 ServeHTTP 传到各 handler 的拨号闭包。独立的类型（不复用 fallback.go 的
// ctxKey）使两处 context 键空间互不干扰。
type dialCtxKey int

const ctxPreferredFamily dialCtxKey = iota

// withPreferredFamily 返回携带出站地址族偏好的 context。addr 为零值时原样返回
// （无偏好 = 使用操作系统默认排序）。
func withPreferredFamily(ctx context.Context, addr netip.Addr) context.Context {
	if !addr.IsValid() {
		return ctx
	}
	return context.WithValue(ctx, ctxPreferredFamily, addr)
}

// preferredFamily 取出拨号应优先使用的地址族，第二个返回值为 false 表示无偏好。
func preferredFamily(ctx context.Context) (netip.Addr, bool) {
	addr, ok := ctx.Value(ctxPreferredFamily).(netip.Addr)
	if !ok || !addr.IsValid() {
		return netip.Addr{}, false
	}
	return addr, true
}

// preferredOrNone 是 preferredFamily 的单返回值形式：无偏好时返回零值，
// dialOutbound 会据此退化为单次拨号。
func preferredOrNone(ctx context.Context) netip.Addr {
	prefer, _ := preferredFamily(ctx)
	return prefer
}

// clientPreferredFamily 从请求的远端地址推导客户端到服务端的地址族。
// IPv4-mapped 的 IPv6 形式（::ffff:a.b.c.d）折叠为 IPv4，使 v4 客户端经双栈
// 监听接入时仍按 IPv4 处理。无法解析时返回零值（=无偏好）。
func clientPreferredFamily(remoteAddr string) netip.Addr {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// normalizeNetwork 把基础网络名具体化为 ip 所属的地址族，使按候选地址逐个
// 拨号成为可能：只有具体的 "tcp4"/"tcp6" 才不会再次触发双栈选择。
// 已经是具体族或其他网络（如 "ip4:icmp"）时原样返回。
func normalizeNetwork(network string, ip netip.Addr) string {
	family := "6"
	if ip.Is4() {
		family = "4"
	}
	switch network {
	case "tcp", "udp", "ip":
		return network + family
	default:
		return network
	}
}

// sortByPreferredFamily 稳定地把 prefer 所属族的地址排到前面，其余地址保持
// 解析器给出的原序（RFC 6724 已经做了合理的排序，这里只调整族的优先级）。
func sortByPreferredFamily(addrs []netip.Addr, prefer netip.Addr) {
	if !prefer.IsValid() || len(addrs) < 2 {
		return
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
	copy(addrs, append(preferred, rest...))
}

// splitDialTarget 把目标拆成主机与端口字符串。没有端口的形态（如没有方括号
// 的裸 IPv6、或调用方传了不带端口的地址）以 port="" 返回，构造出零端口候选。
func splitDialTarget(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return addr, ""
}

// parseDialPort 解析端口字符串，解析失败返回 0（与拆分前"无端口目标"
// 交给拨号层报错的行为一致）。
func parseDialPort(port string) uint16 {
	if port == "" {
		return 0
	}
	n, err := net.LookupPort("tcp", port)
	if err != nil || n < 0 || n > 0xFFFF {
		return 0
	}
	return uint16(n)
}

// orderDialCandidates 解析目标地址并返回候选（已按 prefer 指定的地址族排在
// 前面）。字面 IP 目标只有一个候选，其地址族与偏好无关——目标地址本身已经
// 决定了族。
//
// 域名的候选顺序是"优先地址族"的唯一实现手段：Go 的拨号器把第一个解析结果
// （RFC 6724 排序后通常是 IPv6）当作主地址，另一族要等 FallbackDelay（300ms）
// 之后才被尝试；标准库没有"优先族"开关，而设置 net.Dialer.Resolver 会绕过它
// 内部的双栈选择。因此这里自行解析，把客户端所属族排到前面，另一族仍排在后面
// 作为回退——是偏好而不是硬过滤，目标只有另一族时依旧可连。
func orderDialCandidates(ctx context.Context, addr string, prefer netip.Addr) ([]netip.Addr, error) {
	host, _ := splitDialTarget(addr)

	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}

	ips, err := lookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		addrs = append(addrs, addr.Unmap())
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no usable addresses for %s", host)
	}
	sortByPreferredFamily(addrs, prefer)
	return addrs, nil
}

// dialerConfig 是 dialOutbound 需要的拨号器参数：一次拨号的截止时长与实际
// 的拨号函数。hostDialer 是 net.Dialer 的适配器（net.Dialer.Timeout 是字段
// 而不是方法），测试则用记录型实现替换拨号函数，断言候选顺序与回退行为。
type dialerConfig interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Timeout() time.Duration
}

// hostDialer 把 net.Dialer 适配成 dialerConfig。超时显式保存，使
// dialOutbound 不必依赖 net.Dialer 的字段（也因此不会被误改）。
type hostDialer struct {
	dialer  net.Dialer
	timeout time.Duration
}

func (h *hostDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return h.dialer.DialContext(ctx, network, address)
}

func (h *hostDialer) Timeout() time.Duration { return h.timeout }

// errClientGone 表示拨号期间客户端已经离开（请求 context 被取消）。它是明确的
// 类型而不是裸 context.Canceled：net 会把取消转成 "operation was canceled"
// 的取消错误，其 Is(context.Canceled) 为真，若依赖这一点，拨号失败日志会把
// 客户端拆除与真正的拨号故障混在一起。
var errClientGone = errors.New("client gone")

// dialOutbound 打开一个出站连接：把 network 具体化到候选地址所属的地址族，
// 并按候选顺序（客户端所属族在前）逐个尝试，直到成功。
// 每个候选拿到的预算是整个拨号超时按候选数均分（至少 minDialAttemptTimeout），
// 这样"半个 IPv6 可用"的目标（IPv6 路由黑洞）不会让第一个候选吃满全部预算。
// 没有偏好、或解析失败时退化为单次拨号，把目标原样交给系统解析器。
// ctx 是调用方的 context，客户端中途断开时返回 errClientGone。
func dialOutbound(ctx context.Context, d dialerConfig, network, target string, prefer netip.Addr) (net.Conn, error) {
	if !prefer.IsValid() {
		return d.DialContext(ctx, network, target)
	}

	candidates, err := orderDialCandidates(ctx, target, prefer)
	if err != nil {
		// 解析失败就按系统默认排序拨号：解析器的失败应该表现为拨号层的真实
		// 错误，而不是在这里提前失败。
		log.Debug("[HANDLE] outbound resolve failed, dialing without family preference", "target", target, "err", err)
		return d.DialContext(ctx, network, target)
	}
	_, port := splitDialTarget(target)
	portNum := parseDialPort(port)

	if len(candidates) == 1 {
		resolvedNetwork := normalizeNetwork(network, candidates[0])
		conn, err := d.DialContext(ctx, resolvedNetwork, netip.AddrPortFrom(candidates[0], portNum).String())
		return conn, dialErrOrClientGone(ctx, err)
	}

	perAttempt := max(d.Timeout()/time.Duration(len(candidates)), minDialAttemptTimeout)

	var lastErr error
	for _, candidate := range candidates {
		resolvedNetwork := normalizeNetwork(network, candidate)
		attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
		conn, err := d.DialContext(attemptCtx, resolvedNetwork, netip.AddrPortFrom(candidate, portNum).String())
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			// 客户端已离开：继续尝试其他候选只会浪费拨号预算。
			// 原始错误并入 errClientGone，使日志仍然保留尝试的是什么。
			return nil, fmt.Errorf("%w: %v", errClientGone, err)
		}
	}
	return nil, lastErr
}

// dialErrOrClientGone 把"拨号失败时调用方 context 已经失效"统一标记为
// errClientGone，使上层不必区分是哪个候选触发的取消。
func dialErrOrClientGone(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return errClientGone
	}
	return err
}

// minDialAttemptTimeout 是单个候选拨号预算的下限，避免候选较多时
// 单个候选预算过小而误判失败。
const minDialAttemptTimeout = time.Second

// dialer 是 TCP/UDP/ICMP handler 共享的出站拨号组件：
// next-proxy 路由（带 SSRF 预检查）以及带拨号后 SSRF 防护的直接拨号。
type dialer struct {
	nextProxy *nextproxy.NextProxy
	// shouldProxy 决定 target 是否经由 next proxy 转发。只有当 nextProxy 非 nil
	// 时才会被查询，并且只要设置了 nextProxy 就必须同时设置它：
	// ICMP handler 两者都不设置，因为原始 socket 无法由 SOCKS5 代理承载，
	// 而且它的路径不携带 context。
	shouldProxy func(target string) bool
	// direct 为 target 打开直接出站连接，地址族由实现按目标与 ctx 中的偏好决定。
	direct DirectDial
}

// DirectDial 打开一个出站连接。network 是基础网络名（"tcp"/"udp"/"ip"），
// 具体地址族由实现根据目标与 ctx 中的偏好决定。
type DirectDial func(ctx context.Context, network, target string) (net.Conn, error)

// dialTarget 打开出站连接，并连同可打印的远端地址一起返回用于日志。
// 远端地址在这里解析，因为 next-proxy 路径得到的是 SOCKS5 连接，
// 其 RemoteAddr() 为 nil。
func (d *dialer) dialTarget(ctx context.Context, network, target string) (net.Conn, string, error) {
	if d.nextProxy != nil && d.shouldProxy(target) {
		// 在拨号时重新执行 SSRF 检查：握手时的检查可能已经过去很久，
		// 而 DNS 重绑定域名现在可能解析出不同的结果。下面的拨号后检查
		// 无法在此路径上执行——SOCKS5 连接报告的是代理的地址而不是目标的——
		// 因此代理自身的解析器仍是（可信的、管理员配置的）残余风险。
		if util.IsLANHostResolved(ctx, target) {
			return nil, "", fmt.Errorf("ssrf: rejected lan destination %s", target)
		}
		// 地址族刻意不下推到这一层：这里连的是上游 SOCKS5 代理而不是目标，
		// 把客户端的地址族套到代理地址上只会让上游不可达。
		log.Info("[HANDLE] dialing via next proxy", "target", target, "proxy", d.nextProxy.Host())
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
