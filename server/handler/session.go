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
//
// 它刻意吞掉写入错误：RST 是发给一条已经死掉的流的最佳努力通知，
// 失败（流已被客户端取消、连接已断）没有任何可执行的补救，也会在每条正常
// 拆除的流上制造噪声。这里显式声明该契约，使"不检查返回值"与其他地方的
// PushFrame/PushData 错误检查区分开，而不是看起来像遗漏。
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
// 会让每个流都产生一条这样的错误，因此它们不能按故障记录。
var transientStreamPatterns = []string{
	// HTTP/2 流级取消：标准库用未导出的哨兵包装，只能靠字符串匹配。
	"stream error: stream id ",
	"stream closed",
	// 客户端连接消失：net/http 用它关闭该连接上残留的所有流。
	"client disconnected",
	"client connection lost",
	// net/http：请求体在我们自己关闭（中继终止）之后仍被读取。
	"invalid read on closed body",
	// relay：正常的流生命周期结束。
	"idle timeout",
	"stream drained",
}

// isTransientStreamError 报告流失败是否是预期的拆除路径（对端离开该流、
// 中继空闲超时），而不是真正的故障。这类失败在客户端断开或回收连接时会同时
// 命中许多流，应以 Debug 级别记录，而不是逐流刷满 Info。
//
// 这里刻意不判定 context.Canceled：net 在拨号被取消时返回的取消错误
// （"operation was canceled"）满足 errors.Is(err, context.Canceled)，直接按它
// 归类会把真正的拨号故障一起静音。只有我们自己的 errClientGone 才代表客户端离开。
//
// "connection reset by peer"/"broken pipe" 这类传输层文本则不区分方向：目标侧
// 被 RST（排查被墙主机时最想看到的信号）会一并被静音，因此不列入。
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
// 它现在是纵深防御的断言：拨号前已经用同一次解析的结果校验过候选地址，
// 所有出站连接都只拨那些字面地址，因此正常情况下不会触发。保留它是因为
// 成本为零，且能兜住未来新增的、绕过 dialOutbound 的拨号路径。
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
// 出站地址校验与地址族偏好
// ---------------------------------------------------------------------------

// resolveHost 是全包唯一的域名解析入口；测试替换它以注入确定性的解析结果，
// 使 SSRF 校验与拨号都不依赖真实 DNS。
var resolveHost = util.ResolveHostIPs

// dialCtxKey 是未导出的 context 键类型，把「客户端接入服务端所用的地址族」与
// 「握手阶段解析并校验过的目标地址」从 ServeHTTP 传到各 handler 的拨号路径。
type dialCtxKey int

const (
	ctxPreferredFamily dialCtxKey = iota
	ctxResolvedAddrs
)

// withPreferredFamily 返回携带出站地址族偏好的 context；addr 为零值时原样返回
// （无偏好 = 由系统按 RFC 6724 排序）。
func withPreferredFamily(ctx context.Context, addr netip.Addr) context.Context {
	if !addr.IsValid() {
		return ctx
	}
	return context.WithValue(ctx, ctxPreferredFamily, addr)
}

// preferredFamily 取出拨号应优先使用的地址族，ok 为 false 表示无偏好。
func preferredFamily(ctx context.Context) (netip.Addr, bool) {
	addr, ok := ctx.Value(ctxPreferredFamily).(netip.Addr)
	return addr, ok && addr.IsValid()
}

// withResolvedAddrs 返回携带「握手阶段已解析并校验过的目标地址」的 context。
// 拨号路径优先复用它们，因此一次流只解析一次：检查与连接用的是同一批地址。
func withResolvedAddrs(ctx context.Context, addrs []netip.Addr) context.Context {
	if len(addrs) == 0 {
		return ctx
	}
	return context.WithValue(ctx, ctxResolvedAddrs, addrs)
}

// resolvedAddrs 取出已校验的目标地址，ok 为 false 表示 ctx 中没有（需要自行解析）。
func resolvedAddrs(ctx context.Context) ([]netip.Addr, bool) {
	addrs, ok := ctx.Value(ctxResolvedAddrs).([]netip.Addr)
	return addrs, ok && len(addrs) > 0
}

// clientPreferredFamily 从客户端到服务端的远端地址推导其接入地址族。
// IPv4-mapped 形式（::ffff:a.b.c.d）折叠为 IPv4；无法解析时返回零值（无偏好）。
func clientPreferredFamily(remoteAddr string) netip.Addr {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// preferredFirst 返回按族偏好重排后的候选：prefer 所属族的地址在前，其余保持
// 解析器给出的原序（RFC 6724 已经做了合理的排序，这里只调整族的优先级）。
// 它不修改入参（ctx 里的切片是共享的），且只是偏好而非过滤：目标只有另一族时
// 依旧可连。
func preferredFirst(addrs []netip.Addr, prefer netip.Addr) []netip.Addr {
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
	return append(preferred, rest...)
}

// dialCandidates 返回可拨号的字面地址，并按客户端地址族偏好排序。它优先复用
// 握手阶段已解析并校验过的地址（这一次流不再查 DNS），没有时才自行解析。
// 任一候选为 LAN/私网/保留地址时拒绝整个目标：SSRF 校验与实际连接共用同一
// 批地址，DNS-rebinding 没有在检查与连接之间翻转答案的窗口。
func dialCandidates(ctx context.Context, target string) ([]netip.Addr, error) {
	addrs, ok := resolvedAddrs(ctx)
	if !ok {
		var err error
		addrs, err = resolveHost(ctx, target)
		if err != nil {
			return nil, err
		}
	}
	if lan := util.FirstLANAddr(addrs); lan.IsValid() {
		return nil, fmt.Errorf("ssrf: rejected lan destination %s (target %s)", lan, target)
	}
	prefer, _ := preferredFamily(ctx)
	return preferredFirst(addrs, prefer), nil
}

// errClientGone 表示拨号期间客户端已经离开（请求 context 已失效）。它是显式
// 类型而不是裸 context.Canceled：net 把取消转成 "operation was canceled" 的
// 取消错误，其 Is(context.Canceled) 为真，依赖这一点会让客户端拆除与真正的
// 拨号故障混在一起（见 isTransientStreamError）。
var errClientGone = errors.New("client gone")

// dialAddr 把候选地址拼成拨号用的目标：端口字符串原样沿用（不做服务名重解析），
// 无端口的目标（ICMP）拨裸 IP——给原始套接字的目标带上端口会让 net.Dial 失败。
func dialAddr(addr netip.Addr, target string) string {
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return addr.String()
	}
	return net.JoinHostPort(addr.String(), port)
}

// dialAddrs 逐个拨给定的字面地址。拨号本身由 d.Timeout 限定；全部候选失败时
// 返回最后一个错误，客户端中途离开则返回 errClientGone。
func dialAddrs(ctx context.Context, d *net.Dialer, network, target string, addrs []netip.Addr) (net.Conn, error) {
	var lastErr error
	for _, addr := range addrs {
		conn, err := d.DialContext(ctx, network, dialAddr(addr, target))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %v", errClientGone, err)
		}
	}
	return nil, lastErr
}

// dialOutbound 解析并校验目标（域名只解析一次，优先复用握手结果），然后只拨
// 校验过的字面地址。目标原文永远不会传给拨号器，避免产生第二次、未校验的解析。
func dialOutbound(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
	addrs, err := dialCandidates(ctx, target)
	if err != nil {
		return nil, err
	}
	return dialAddrs(ctx, d, network, target, addrs)
}

// outboundDialer 返回直接出站拨号器；keepAlive 为 0 表示系统默认
// （UDP/ICMP 没有长连接语义）。Timeout 必须显式设置：dialOutbound 自己不设
// 截止时间，缺少它会让拨号在 SYN 黑洞（被墙目标的常态）上一直挂到客户端放弃。
func outboundDialer(timeout, keepAlive time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
}

// dialer 是 TCP/UDP/ICMP handler 共享的出站拨号组件：
// next-proxy 路由（带尽力而为的 SSRF 预检查，见 dialTarget）以及只拨校验过的
// 字面地址的直接拨号（带拨号后的纵深防御断言）。
type dialer struct {
	nextProxy *nextproxy.NextProxy
	// shouldProxy 决定 target 是否经由 next proxy 转发。只有当 nextProxy 非 nil
	// 时才会被查询，并且只要设置了 nextProxy 就必须同时设置它：
	// ICMP handler 两者都不设置，因为原始 socket 无法由 SOCKS5 代理承载。
	shouldProxy func(target string) bool
	// direct 打开直接出站连接，地址族由 dialOutbound 按 ctx 中的偏好决定。
	direct func(ctx context.Context, network, target string) (net.Conn, error)
}

// dialTarget 打开出站连接，并连同可打印的远端地址一起返回用于日志。
// 远端地址在这里解析，因为 next-proxy 路径得到的是 SOCKS5 连接，
// 其 RemoteAddr() 为 nil。
func (d *dialer) dialTarget(ctx context.Context, network, target string) (net.Conn, string, error) {
	if d.nextProxy != nil && d.shouldProxy(target) {
		// 这条路径**有意**保持「把域名交给上游代理解析」的语义，因此 SSRF 检查
		// 与实际连接是两次不同的解析：代理是管理员配置的可信组件，其自身解析器
		// 是明确接受的残余风险（而不是遗漏）。这里的检查只是尽力而为的早退，
		// 并复用握手阶段的解析结果；解析失败时放行（让代理去解析），因为被墙/
		// 仅代理侧可解析的域名正是 next proxy 的用途之一。要彻底关掉这个窗口，
		// 需要改成把服务端解析并校验过的字面 IP 交给代理——那会牺牲上述场景，
		// 因此没有默认启用。
		addrs, ok := resolvedAddrs(ctx)
		if !ok {
			var err error
			if addrs, err = resolveHost(ctx, target); err != nil {
				log.Debug("[HANDLE] next proxy target resolve failed, handing the name to the proxy", "target", target, "err", err)
			}
		}
		if lan := util.FirstLANAddr(addrs); lan.IsValid() {
			return nil, "", fmt.Errorf("ssrf: rejected lan destination %s (target %s)", lan, target)
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
