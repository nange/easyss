package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/relay"
	"github.com/nange/easyss/v3/util/netbuf"

	sharedconfig "github.com/nange/easyss/v3/config"
)

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

// routeDecision 是一次分流判定。IPV6Rejected 与 Block 同义，但需要单独提示用户原因。
type routeDecision struct {
	Action       routeAction
	IPV6Rejected bool
}

type routePolicyOptions struct {
	Router            *router.Router
	Dial              func(ctx context.Context, network, addr string) (net.Conn, error)
	DialTimeout       time.Duration
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

// decide 判定目标主机的分流动作。router 为 nil 时 ClassifyHost 自身会回落到 Proxy。
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
	r := netbuf.NewReader(protocol.MinRecordBufferSize, sharedconfig.TCPStreamBufferSize)
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
