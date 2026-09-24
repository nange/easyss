package proxy

import (
	"context"
	"errors"
	"io"
	"net"
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
)

func (a routeAction) String() string {
	switch a {
	case routeBlock:
		return "block"
	case routeDirect:
		return "direct"
	default:
		return "proxy"
	}
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
}

// routePolicy 是两个入口共用的分流策略。
type routePolicy struct {
	router            *router.Router
	dial              func(ctx context.Context, network, addr string) (net.Conn, error)
	dialTimeout       time.Duration
	streamIdleTimeout time.Duration
}

func newRoutePolicy(opts routePolicyOptions) *routePolicy {
	return &routePolicy{
		router:            opts.Router,
		dial:              opts.Dial,
		dialTimeout:       opts.DialTimeout,
		streamIdleTimeout: opts.StreamIdleTimeout,
	}
}

// decide 判定目标主机的分流动作。router 为 nil（测试中的裸服务器）时
// ClassifyHost 自身会回落到 Proxy，因此这里无需额外分支。
func (p *routePolicy) decide(host string) routeDecision {
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
