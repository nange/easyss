package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/relay"
	"github.com/nange/easyss/v3/util/netbuf"

	"github.com/nange/easyss/v3/config"
)

// routeAction 是一次分流判定的结果。
type routeAction uint8

const (
	routeBlock routeAction = iota
	routeDirect
	routeProxy
	routeVPN
)

func (a routeAction) String() string {
	switch a {
	case routeBlock:
		return "block"
	case routeDirect:
		return "direct"
	case routeVPN:
		return "vpn"
	default:
		return "proxy"
	}
}

// VPNRoute 是访问侧 VPN 的注入面：把「目标是不是本机配置的对端」与「两条经隧道的
// 拨号路径」暴露给代理层，nil 表示功能关闭。接口定义在消费方（本包）而不是
// vpn/node——对端面复用的正是本包的 Socks5Server，反过来依赖会形成导入环。
type VPNRoute interface {
	// Lookup 判断 host（对端名或 overlay 字面 IP）是否为本机配置的对端，并返回它的
	// 规范名（host_name）。规范名用于会话键：两种书写形式必须落在同一条流上。
	Lookup(host string) (canonical string, ok bool)
	// DialTCP 打开一条经隧道到对端服务端口的连接。target 是访问侧看到的原始目标。
	DialTCP(ctx context.Context, target string) (net.Conn, error)
	// DialUDP 打开一条经隧道到对端服务端口的 UDP 流；返回的连接在首次写入时自动
	// 补上一次性目标头（见 vpn/node/udprelay.go 的 EncodeUDPTarget）。
	DialUDP(ctx context.Context, target string) (net.Conn, error)
}

// VPNStaticNames 是 VPNRoute 的**可选**扩展：实现它的访问侧能为对端名字就地应答 DNS。
// 做成可选能力而不是第二个注入字段，是因为注入的本来就是同一个对象（vpn/node.Route
// 同时实现两者），不实现它的注入面只是让对端名字回到普通转发路径。
type VPNStaticNames interface {
	// ResolveStatic 报告 name（DNS 问题名，末尾带根点）是否为本机配置的对端名。
	ResolveStatic(name string) (netip.Addr, bool)
}

// routeDecision 是一次分流判定：动作，以及目标是否被 ipv6 策略门拒绝
// （后者与 Block 同义，但需要单独提示用户原因）。
type routeDecision struct {
	Action       routeAction
	IPV6Rejected bool
}

type routePolicyOptions struct {
	Router            *router.Router
	Dial              func(ctx context.Context, network, addr string) (net.Conn, error)
	DialTimeout       time.Duration
	StreamIdleTimeout time.Duration
	// VPN 为 nil 时 VPN 分流完全关闭，行为与既有版本一致。
	VPN VPNRoute
}

// routePolicy 是两个入口共用的分流策略。
type routePolicy struct {
	router            *router.Router
	dial              func(ctx context.Context, network, addr string) (net.Conn, error)
	dialTimeout       time.Duration
	streamIdleTimeout time.Duration
	vpn               VPNRoute
}

func newRoutePolicy(opts routePolicyOptions) *routePolicy {
	return &routePolicy{
		router:            opts.Router,
		dial:              opts.Dial,
		dialTimeout:       opts.DialTimeout,
		streamIdleTimeout: opts.StreamIdleTimeout,
		vpn:               opts.VPN,
	}
}

// decide 判定目标主机的分流动作。router 为 nil 时 ClassifyHost 自身会回落到 Proxy。
//
// VPN 对端必须在 router 之前判定：host_name 与 overlay IP 只有本机认识，交给
// GeoIP/域名列表只会得到"未知 → 走代理"，目标被送进服务端后表现为一次 DNS 失败。
func (p *routePolicy) decide(host string) routeDecision {
	if p.vpn != nil {
		if _, ok := p.vpn.Lookup(host); ok {
			return routeDecision{Action: routeVPN}
		}
	}
	cls := p.router.ClassifyHost(host)
	decision := routeDecision{IPV6Rejected: cls.IPV6Rejected}
	switch cls.Rule {
	case router.HostRuleBlock:
		decision.Action = routeBlock
	case router.HostRuleDirect:
		decision.Action = routeDirect
	default:
		decision.Action = routeProxy
	}
	return decision
}

func (p *routePolicy) dialDirect(target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.dialTimeout)
	defer cancel()
	return p.dial(ctx, "tcp", target)
}

func (p *routePolicy) streamIdle() time.Duration {
	return p.streamIdleTimeout
}

// logRouteDecision 以两个入口一致的字段记录一次分流判定，prefix 区分入口（"[TCP]" /
// "[HTTP-PROXY]"），使同一条规则在两处的日志可以对照阅读。
func logRouteDecision(prefix string, decision routeDecision, host, target, local string) {
	log.Info(prefix+" "+decision.Action.String(), "host", host, "target", target, "local", local)
}

func logRouteIPV6Rejected(prefix, target string) {
	log.Warn(prefix+" ipv6 target rejected, ipv6 disabled", "target", target)
}

// relayTCP 在 dst 与 src 之间双向拷贝字节，共用一个空闲超时，镜像代理路径的中继语义：
// 干净 EOF 时传播半关闭，空闲超时或出错时两个连接恰好关闭一次。这里刻意不做速度记账：
// upload_speed/download_speed 只统计经隧道的流量，两个入口共用本函数。
func relayTCP(dst, src net.Conn, idleTimeout time.Duration) {
	result := relay.Bidirectional(idleTimeout, relay.CloseBoth(dst, src),
		func(signalActivity func()) error { return copyHalfClose(dst, src, signalActivity) },
		func(signalActivity func()) error { return copyHalfClose(src, dst, signalActivity) },
	)
	logRelayResult("[TCP] direct", "", result)
}

// logRelayResult 记录一次结束的中继：预期的拆除保持静默，超时或拷贝失败记 Debug。
func logRelayResult(prefix, target string, result relay.Result) {
	if result.Err == nil || errors.Is(result.Err, io.EOF) || errors.Is(result.Err, io.ErrClosedPipe) || isLocalConnClosedError(result.Err) {
		return
	}
	if result.TimedOut {
		log.Debug(prefix+" stream idle timeout", "target", target, "err", result.Err)
		return
	}
	log.Debug(prefix+" relay copy error", "target", target, "err", result.Err)
}

// copyHalfClose 将 src 流式拷贝到 dst，每次读取发出活动信号，干净 EOF 时对 dst 执行
// 半关闭。读缓冲按需增长（起点 protocol.MinRecordBufferSize，上限 TCPStreamBufferSize）。
func copyHalfClose(dst, src net.Conn, signalActivity func()) error {
	r := netbuf.NewReader(protocol.MinRecordBufferSize, config.TCPStreamBufferSize)
	defer r.Release()
	for {
		buf := r.Buf()
		n, rErr := src.Read(buf)
		if n > 0 {
			signalActivity()
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
			// 写完之后才换档：Grow 会把 buf 归还池。
			if n == len(buf) {
				r.Grow()
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				if cw, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				return nil
			}
			return rErr
		}
	}
}
