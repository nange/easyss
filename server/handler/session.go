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
// 出站地址族偏好
// ---------------------------------------------------------------------------

// lookupNetIP 解析域名的指定地址族（"ip4"/"ip6"）地址；测试替换它以注入
// 确定性的解析结果，使拨号不依赖真实 DNS。
var lookupNetIP = net.DefaultResolver.LookupNetIP

// dialCtxKey 是未导出的 context 键类型，把"客户端接入服务端所用的地址族"
// 从 ServeHTTP 传到各 handler 的拨号路径。
type dialCtxKey int

const ctxPreferredFamily dialCtxKey = iota

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

// clientPreferredFamily 从客户端到服务端的远端地址推导其接入地址族。
// IPv4-mapped 形式（::ffff:a.b.c.d）折叠为 IPv4；无法解析时返回零值（无偏好）。
func clientPreferredFamily(remoteAddr string) netip.Addr {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// preferredTarget 把 host:port 中的域名解析为 prefer 所属族的地址，返回
// "ip:port"。字面 IP 目标（族已由目标自身决定）、无端口、无偏好、解析失败或
// 该族没有地址时返回空串，调用方随即退回目标原文——因此这只是偏好而非过滤，
// 目标只有另一族时依旧可连。
func preferredTarget(ctx context.Context, target string, prefer netip.Addr) string {
	if !prefer.IsValid() {
		return ""
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	family := "ip6"
	if prefer.Is4() {
		family = "ip4"
	}
	ips, err := lookupNetIP(ctx, family, host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return net.JoinHostPort(ips[0].Unmap().String(), port)
}

// errClientGone 表示拨号期间客户端已经离开（请求 context 已失效）。它是显式
// 类型而不是裸 context.Canceled：net 把取消转成 "operation was canceled" 的
// 取消错误，其 Is(context.Canceled) 为真，依赖这一点会让客户端拆除与真正的
// 拨号故障混在一起（见 isTransientStreamError）。
var errClientGone = errors.New("client gone")

// dialOutbound 打开一个出站连接。域名目标先拨客户端所属族的地址（VPS 上系统
// 往往先试 IPv6），该族不可用时退回目标原文、由系统重新解析并做双栈回退。
// 拨号本身由 d.Timeout 限定。
func dialOutbound(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
	prefer, _ := preferredFamily(ctx)

	if resolved := preferredTarget(ctx, target, prefer); resolved != "" {
		conn, err := d.DialContext(ctx, network, resolved)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %v", errClientGone, err)
		}
	}

	conn, err := d.DialContext(ctx, network, target)
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("%w: %v", errClientGone, err)
	}
	return conn, err
}

// outboundDialer 返回直接出站拨号器；keepAlive 为 0 表示系统默认
// （UDP/ICMP 没有长连接语义）。Timeout 必须显式设置：dialOutbound 自己不设
// 截止时间，缺少它会让拨号在 SYN 黑洞（被墙目标的常态）上一直挂到客户端放弃。
func outboundDialer(timeout, keepAlive time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
}

// dialer 是 TCP/UDP/ICMP handler 共享的出站拨号组件：
// next-proxy 路由（带 SSRF 预检查）以及带拨号后 SSRF 防护的直接拨号。
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
