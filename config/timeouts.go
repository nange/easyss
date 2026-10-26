package config

import "time"

// 基础超时（秒）的唯一合法性入口：非正值取 DefaultTimeout，其余钳制到区间内。
func NormalizeTimeout(sec int) int {
	if sec <= 0 {
		return DefaultTimeout
	}
	return min(max(sec, MinTimeout), MaxTimeout)
}

func TimeoutDuration(sec int) time.Duration {
	return time.Duration(NormalizeTimeout(sec)) * time.Second
}

// TCP 流空闲超时（8 倍 base）：传输层的空闲计时器只在连接上没有打开的流时才计时，
// 静默但存活的流靠中继在这里判死。
func StreamIdleTimeout(base time.Duration) time.Duration {
	return 8 * base
}

// net/http 空闲连接超时（6 倍 base）：客户端在服务端 h2 空闲回收（默认 8 倍）与连接
// 轮换（12 倍）之前收起空闲连接，避免对端先发 GOAWAY。
func IdleConnTimeout(base time.Duration) time.Duration {
	return 6 * base
}

// 连接被轮换前的最大存活时长（12 倍 base）。到期后槽位停收新流而进行中的流不被打断，
// 因此不必严格大于 StreamIdleTimeout。
func ConnLifetime(base time.Duration) time.Duration {
	return 12 * base
}

// UDP 会话的空闲/读取超时（2 倍 base）。
func UDPIdleTimeout(base time.Duration) time.Duration {
	return 2 * base
}

// 出站拨号超时：base/3，限制在 [3s, 15s]。
func DialTimeout(base time.Duration) time.Duration {
	d := min(max(base/3, 3*time.Second), 15*time.Second)
	return d
}

// 消费方只读字段，绝不自己判断零值：填充只发生在 Normalize，否则同一目标会在不同入口
// 拿到不同的超时。
type Timeouts struct {
	Base         time.Duration // 用户配置的基础超时
	Dial         time.Duration // 出站拨号（base/3，限制在 [3s,15s]）
	StreamIdle   time.Duration // TCP 流空闲（8 倍 base）
	UDPIdle      time.Duration // UDP 会话空闲（2 倍 base）
	DNSResp      time.Duration // DNS 响应读取空闲（base/3，不限制）
	IdleConn     time.Duration // net/http 空闲连接（6 倍 base）
	ConnLifetime time.Duration // 传输层连接轮换前的最大存活时长（12 倍 base）
}

func NewTimeouts(base time.Duration) Timeouts {
	if base <= 0 {
		base = time.Duration(DefaultTimeout) * time.Second
	}
	return Timeouts{
		Base:         base,
		Dial:         DialTimeout(base),
		StreamIdle:   StreamIdleTimeout(base),
		UDPIdle:      UDPIdleTimeout(base),
		DNSResp:      base / 3,
		IdleConn:     IdleConnTimeout(base),
		ConnLifetime: ConnLifetime(base),
	}
}

// Normalize 只填零值字段，显式给出的字段一律保留，且不钳制 Base——区间钳制属于用户输入，
// 见 NormalizeTimeout。
func (t Timeouts) Normalize() Timeouts {
	normalized := t
	if normalized.Base <= 0 {
		normalized.Base = TimeoutDuration(0)
	}
	if normalized.Dial <= 0 {
		normalized.Dial = DialTimeout(normalized.Base)
	}
	if normalized.StreamIdle <= 0 {
		normalized.StreamIdle = StreamIdleTimeout(normalized.Base)
	}
	if normalized.UDPIdle <= 0 {
		normalized.UDPIdle = UDPIdleTimeout(normalized.Base)
	}
	if normalized.DNSResp <= 0 {
		normalized.DNSResp = normalized.Base / 3
	}
	if normalized.IdleConn <= 0 {
		normalized.IdleConn = IdleConnTimeout(normalized.Base)
	}
	if normalized.ConnLifetime <= 0 {
		normalized.ConnLifetime = ConnLifetime(normalized.Base)
	}
	return normalized
}
