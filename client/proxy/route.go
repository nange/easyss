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
	"github.com/nange/easyss/v3/relay"
	"github.com/nange/easyss/v3/util/bytespool"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// 本文件是本地代理的分流策略：把「目标主机 → Block/Direct/Proxy」的判定、
// 直连拨号与直连中继集中在一处，供 SOCKS5 与 HTTP 两个入口共用。此前两个入口
// 各自复制了一份判定（routeTCP 与 handleConnect），Block/IPv6 语义的改动需要
// 同时改两处，且两侧的日志字段已经出现偏离。

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

// VPNRoute 是访问侧 VPN 的注入面（见 docs/vpn-design.md 5.3）：把「目标是不是
// 本机配置的对端」与「两条经隧道的拨号路径」暴露给代理层。三处注入式改动
// （decide、routeTCPReplied、handleRegularUDP）都以它为界，nil 表示功能关闭。
//
// 接口定义在消费方（本包）而不是 vpn/node，因为 vpn/node 已经依赖本包——对端面
// 复用的正是 Socks5Server（见 vpn/node/peerface.go）；反过来依赖会形成导入环。
type VPNRoute interface {
	// Lookup 判断 host（对端名或 overlay 字面 IP）是否为本机配置的对端，并返回
	// 它的规范名（host_name）。规范名用于会话键：同一个对端的两种书写形式必须
	// 落在同一条流上，否则按 overlay IP 与按名字访问会各自建一条隧道。
	Lookup(host string) (canonical string, ok bool)
	// DialTCP 打开一条经隧道到对端服务端口的 TCP 连接。target 是访问侧看到的
	// 原始目标（host:port）；把它归一化成字面 127.0.0.1:<port> 是实现内部的事
	// （内层 CONNECT 契约，见 5.1）。
	DialTCP(ctx context.Context, target string) (net.Conn, error)
	// DialUDP 打开一条经隧道到对端服务端口的 UDP 流。返回的连接在首次写入时
	// 自动补上一次性目标头（见 vpn/node/udprelay.go 的 EncodeUDPTarget），因此
	// 调用方只需按普通 net.Conn 收发数据报。
	DialUDP(ctx context.Context, target string) (net.Conn, error)
}

// VPNStaticNames 是 VPNRoute 的**可选**扩展：实现它的访问侧能为对端名字就地
// 应答 DNS（见 docs/vpn-design.md 5.4）。
//
// 做成可选能力而不是第二个注入字段，是因为注入的本来就是同一个对象
// （`vpn/node.Route` 同时实现两者，runner 只把它交给 `Socks5Options.VPN`）：
// 再加一个"必须与 VPN 保持同步"的字段只会多一处可以写错的地方。不实现它的
// 注入面只是让对端名字回到普通转发路径。
//
// 这个钩子必须存在于**代理的 DNS 拦截器**上：TUN 模式写进系统解析器的是一个
// 公网 DNS（`cmd/easyss` 的 tunDNS/PreferredSystemDNS），查询经 TUN 到达本包
// 的拦截器，而不是 `client/dns` 的转发服务器（那个只服务 enable_forward_dns
// 的 LAN 部署）。
type VPNStaticNames interface {
	// ResolveStatic 报告 name 是否为本机配置的对端名，并给出它的 overlay IPv4。
	// name 是 DNS 问题名（末尾带根点）。
	ResolveStatic(name string) (netip.Addr, bool)
}

// routeDecision 是一次分流判定：动作，以及目标是否被 ipv6 策略门拒绝
// （后者与 Block 同义，但需要单独提示用户原因）。
type routeDecision struct {
	Action       routeAction
	IPV6Rejected bool
}

type routePolicyOptions struct {
	Router *router.Router
	// Dial 打开直连连接（由各入口注入自己的拨号函数）。
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// DialTimeout 约束一次直连拨号。
	DialTimeout time.Duration
	// StreamIdleTimeout 是直连 TCP 中继的空闲超时。
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

// decide 判定目标主机的分流动作。router 为 nil（测试中的裸服务器）时
// ClassifyHost 自身会回落到 Proxy，因此这里无需额外分支。
//
// VPN 对端在**调用 router 之前**判定：host_name 与 overlay IP 都是只有本机才知道
// 的名字，交给 GeoIP/域名列表去猜只会得到"未知 → 走代理"这个错误答案——那样目标
// 会被送进 easyss 服务器（它同样不认识这个名字），表现为一次 DNS 失败而不是一次
// 隧道访问。
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

// dialDirect 以拨号超时打开一条直连连接。
func (p *routePolicy) dialDirect(target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.dialTimeout)
	defer cancel()
	return p.dial(ctx, "tcp", target)
}

// streamIdle 返回直连中继使用的空闲超时。
func (p *routePolicy) streamIdle() time.Duration {
	return p.streamIdleTimeout
}

// logRouteDecision 以两个入口一致的字段记录一次分流判定。prefix 区分入口
// （"[TCP]" / "[HTTP-PROXY]"），使同一条规则在两个入口上的日志可以对照阅读。
// ipv6 策略门禁不走这里：它是告警而不是普通分流（见 logRouteIPV6Rejected）。
func logRouteDecision(prefix string, decision routeDecision, host, target, local string) {
	log.Info(prefix+" "+decision.Action.String(), "host", host, "target", target, "local", local)
}

// logRouteIPV6Rejected 记录一次被 ipv6 策略门拒绝的分流。
func logRouteIPV6Rejected(prefix, target string) {
	log.Warn(prefix+" ipv6 target rejected, ipv6 disabled", "target", target)
}

// relayTCP 在 dst 与 src 之间双向拷贝字节，共用一个空闲超时，镜像代理路径的
// 中继语义：干净 EOF 时传播半关闭，空闲超时或出错时两个连接恰好关闭一次。
//
// idleTimeout 限制中继在两条连接被拆除前可保持空闲的时长，使沉默或半开的对端
// 无法让两个拷贝 goroutine 及其 socket 永久存活。调用方由用户配置的基础超时
// 派生它（config.StreamIdleTimeout），使直连路径与代理路径的流空闲超时一致。
//
// copyHalfClose 刻意不做速度记账：托盘与 /stats 的 upload_speed/download_speed
// 只统计经隧道的流量（TCP 见 stream.go 的 copyLocalToRemote/copyRemoteToLocal，
// UDP 见 UDPExchange.Send/Receive），直连流量不经服务器。直连 UDP 的
// directUDPRelay/directUDPReadLoop 遵循同一口径；两个入口（SOCKS5 与 HTTP
// 代理）共用本函数，因此这条规则只需要在这里保持一次。
func relayTCP(dst, src net.Conn, idleTimeout time.Duration) {
	result := relay.Bidirectional(idleTimeout, relay.CloseBoth(dst, src),
		func(signalActivity func()) error { return copyHalfClose(dst, src, signalActivity) },
		func(signalActivity func()) error { return copyHalfClose(src, dst, signalActivity) },
	)
	logRelayResult("[TCP] direct", "", result)
}

// logRelayResult 以与结果相匹配的级别记录一次结束的中继：预期的拆除保持静默，
// 超时或拷贝失败记录为 Debug。直连与代理 TCP 路径共用，使同一情况不会被记录为
// 不同级别（直连路径过去会吞掉空闲超时）。
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

// copyHalfClose 将 src 流式拷贝到 dst，每次读取时发出活动信号，并在干净 EOF
// 时对 dst 执行半关闭。
func copyHalfClose(dst, src net.Conn, signalActivity func()) error {
	buf := bytespool.Get(sharedconfig.TCPStreamBufferSize)
	defer bytespool.MustPut(buf)
	for {
		n, rErr := src.Read(buf)
		if n > 0 {
			signalActivity()
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
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
