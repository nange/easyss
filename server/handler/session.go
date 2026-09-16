package handler

import (
	"context"
	"fmt"
	"net"
	"strings"

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

// dialer 是 TCP/UDP/ICMP handler 共享的出站拨号组件：
// next-proxy 路由（带 SSRF 预检查）以及带拨号后 SSRF 防护的直接拨号。
type dialer struct {
	nextProxy *nextproxy.NextProxy
	// useProxy 决定 target 是否经由 next proxy 转发。只有当 nextProxy 非 nil
	// 时才会被查询，并且只要设置了 nextProxy 就必须同时设置它：
	// ICMP handler 两者都不设置，因为原始 socket 无法由 SOCKS5 代理承载，
	// 而且它的路径不携带 context。
	useProxy func(target string) bool
	// dial 为 target 打开直接出站连接。
	dial func(ctx context.Context, network, target string) (net.Conn, error)
}

// dialTarget 打开出站连接，并连同可打印的远端地址一起返回用于日志。
// 远端地址在这里解析，因为 next-proxy 路径得到的是 SOCKS5 连接，
// 其 RemoteAddr() 为 nil。
func (d *dialer) dialTarget(ctx context.Context, network, target string) (net.Conn, string, error) {
	if d.nextProxy != nil && d.useProxy(target) {
		// 在拨号时重新执行 SSRF 检查：握手时的检查可能已经过去很久，
		// 而 DNS 重绑定域名现在可能解析出不同的结果。下面的拨号后检查
		// 无法在此路径上执行——SOCKS5 连接报告的是代理的地址而不是目标的——
		// 因此代理自身的解析器仍是（可信的、管理员配置的）残余风险。
		if util.IsLANHostResolved(ctx, target) {
			return nil, "", fmt.Errorf("ssrf: rejected lan destination %s", target)
		}
		log.Info("[HANDLE] dialing via next proxy", "target", target, "proxy", d.nextProxy.Host())
		conn, err := d.nextProxy.DialContext(ctx, network, target)
		if err != nil {
			return nil, "", err
		}
		return conn, d.nextProxy.Host(), nil
	}
	conn, err := d.dial(ctx, network, target)
	if err != nil {
		return nil, "", err
	}
	if err := rejectLANConn(conn); err != nil {
		return nil, "", err
	}
	return conn, remoteString(conn), nil
}
