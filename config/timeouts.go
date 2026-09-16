package config

import "time"

// 超时派生辅助函数：用户配置的基础超时如何映射到各空闲/拨号超时的唯一事实来源。
// 客户端（runner.Run）和服务端（server.New）都通过这些函数派生各自的超时，
// 因此对任一公式的修改会同时作用于两侧，以及镜像该派生的测试。
//
// 基础超时以参数形式传入：这些函数本身从不读取配置，由调用方传入其自身配置的
// 值（默认 30s，见 DefaultTimeout）。

// StreamIdleTimeout 返回从用户配置的基础超时派生的 TCP 流空闲超时
// （4 倍 base；默认 30s -> 120s）。该倍数限定了流在中继将其拆除前可以完全静默
// 的最长时间：既要足够宽裕以容忍缓慢、空闲的连接（SSH、长轮询），
// 又要能及时回收半开或已死的对端。
func StreamIdleTimeout(base time.Duration) time.Duration {
	return 4 * base
}

// UDPIdleTimeout 返回 UDP 会话的空闲/读取超时（2 倍 base；默认 30s -> 60s）。
func UDPIdleTimeout(base time.Duration) time.Duration {
	return 2 * base
}

// DialTimeout 返回出站拨号超时：base / 3，并限制在 [3s, 15s] 范围内。
// 客户端（直连拨号）与服务端（TCP handler 拨号）共用，确保两侧始终派生出相同的值。
func DialTimeout(base time.Duration) time.Duration {
	d := min(max(base/3, 3*time.Second), 15*time.Second)
	return d
}

// Timeouts 是一个 core 所需的完整派生超时集合。调用方基于配置的基础超时一次性
// 构建它并向下传递，而不是各层各自重新计算（甚至更糟地手写）某个值——此前客户端
// 直接把 timeout/3 用作 DNS 响应超时，而服务端则通过 DialTimeout 派生其拨号超时。
type Timeouts struct {
	Base       time.Duration // 用户配置的基础超时
	Dial       time.Duration // 出站拨号（base/3，限制在 [3s,15s]）
	StreamIdle time.Duration // TCP 流空闲（4 倍 base）
	UDPIdle    time.Duration // UDP 会话空闲（2 倍 base）
	DNSResp    time.Duration // DNS 响应读取空闲（base/3，不限制）
}

// NewTimeouts 从用户配置的基础超时派生整个超时集合
// （当 base <= 0 时应用默认值）。
func NewTimeouts(base time.Duration) Timeouts {
	if base <= 0 {
		base = time.Duration(DefaultTimeout) * time.Second
	}
	return Timeouts{
		Base:       base,
		Dial:       DialTimeout(base),
		StreamIdle: StreamIdleTimeout(base),
		UDPIdle:    UDPIdleTimeout(base),
		DNSResp:    base / 3,
	}
}
