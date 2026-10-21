package http2

import (
	"sync"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// 每个窗口最多逐条打印 slowRTTLogQuota 条样本，其余只计数并在窗口结束时汇成一条：
// 链路整体变差时逐条打印只会刷满日志。窗口滚动由下一条样本或健康循环的兜底冲刷驱动。
const (
	slowRTTLogWindow = 10 * time.Second
	slowRTTLogQuota  = 3
)

// 慢路径 RTT 样本的来源。
const (
	slowRTTSourceStream = "stream" // 代理请求的引导往返
	slowRTTSourceProbe  = "probe"  // 后台主动探测
)

// slowRTTSample 把慢样本归因到具体请求。
type slowRTTSample struct {
	// source 区分样本来自哪条路径。
	source string
	// endpoint 是协议端点。
	endpoint string
	// target 是目标 "host:port"，探测没有目标，留空。
	target string
	// slot 为 nil（测试里裸构造的流）时省略槽位属性。
	slot *transportSlot
}

// slowRTTLogLimiter 是慢路径 RTT 日志的限流器，每个传输层实例一个。
type slowRTTLogLimiter struct {
	// 零值回落到包级默认值；用例可构造更小的值而不必真的等 10 秒。
	window time.Duration
	quota  int

	mu         sync.Mutex
	windowEnd  time.Time // 当前窗口结束时刻，零值表示还没有样本
	logged     int       // 当前窗口已逐条打印的样本数
	suppressed int       // 当前窗口被配额压掉的样本数
	worstD     time.Duration
	worst      slowRTTSample
}

func newSlowRTTLogLimiter() *slowRTTLogLimiter {
	return &slowRTTLogLimiter{window: slowRTTLogWindow, quota: slowRTTLogQuota}
}

func (l *slowRTTLogLimiter) windowSize() time.Duration {
	if l.window > 0 {
		return l.window
	}
	return slowRTTLogWindow
}

func (l *slowRTTLogLimiter) quotaPerWindow() int {
	if l.quota > 0 {
		return l.quota
	}
	return slowRTTLogQuota
}

// log 提交一次 RTT 样本：低于阈值丢弃，有配额就逐条打印，否则只记账。nil 接收者表示
// 未配置限流，仍按阈值打印——限流是噪声策略，不该决定日志是否存在。
func (l *slowRTTLogLimiter) log(d time.Duration, s slowRTTSample) {
	if d < config.SlowRTTWarnThreshold {
		return
	}
	if l == nil {
		writeSlowRTTSample(d, s)
		return
	}

	now := time.Now()
	l.mu.Lock()
	summary := l.rollLocked(now)
	emit := l.logged < l.quotaPerWindow()
	if emit {
		l.logged++
	} else {
		l.suppressed++
		if d > l.worstD {
			l.worstD = d
			l.worst = s
		}
	}
	l.mu.Unlock()

	// 日志写在锁外：handler 的写入不该让同时落定的其他采样在锁上排队。
	if summary != nil {
		writeSlowRTTSummary(*summary)
	}
	if emit {
		writeSlowRTTSample(d, s)
	}
}

// flushDue 在窗口结束时把被压掉的样本汇成一条记录：突发结束后没有新样本触发滚动，
// 只能靠健康循环这个周期性调用交代最后一批。
func (l *slowRTTLogLimiter) flushDue(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	summary := l.rollLocked(now)
	l.mu.Unlock()
	if summary != nil {
		writeSlowRTTSummary(*summary)
	}
}

// rollLocked 在窗口到期时开启新窗口并返回上一窗口的汇总（无压掉样本时为 nil）。
// 窗口起点取第一个样本到来的时刻，空闲期不消耗配额。
func (l *slowRTTLogLimiter) rollLocked(now time.Time) *slowRTTSummary {
	if l.windowEnd.IsZero() {
		l.windowEnd = now.Add(l.windowSize())
		return nil
	}
	if now.Before(l.windowEnd) {
		return nil
	}

	var summary *slowRTTSummary
	if l.suppressed > 0 {
		summary = &slowRTTSummary{
			window:     l.windowSize(),
			suppressed: l.suppressed,
			worstD:     l.worstD,
			worst:      l.worst,
		}
	}
	l.windowEnd = now.Add(l.windowSize())
	l.logged = 0
	l.suppressed = 0
	l.worstD = 0
	l.worst = slowRTTSample{}
	return summary
}

// slowRTTSummary 是一个窗口内被压掉的慢样本的汇总。
type slowRTTSummary struct {
	window     time.Duration
	suppressed int
	worstD     time.Duration
	worst      slowRTTSample
}

// writeSlowRTTSample 打印一条慢样本，带上身份与槽位状态：托盘的 RTT 只是全局平均值。
func writeSlowRTTSample(d time.Duration, s slowRTTSample) {
	attrs := []any{
		"rtt", d.Round(time.Millisecond),
		// 属性名不能叫 source：它是 slog 的内建键，handler 会按 *slog.Source 断言
		// 其值并 panic。
		"origin", s.source,
		"endpoint", s.endpoint,
		"proto", protoOfEndpoint(s.endpoint),
	}
	if s.target != "" {
		attrs = append(attrs, "target", s.target)
	}
	if s.slot != nil {
		// active 含本流自己（采样时它仍然活跃），与传输层统计口径一致。
		active := int(s.slot.active.Load())
		attrs = append(attrs,
			"slot", s.slot.idx,
			"slot_state", slotStatus(s.slot, active),
			"active_streams", active)
	}
	log.Warn("[TRANSPORT] slow path RTT sample", attrs...)
}

// writeSlowRTTSummary 打印配额汇总。槽位属性被刻意省略：它是采样时刻的状态。
func writeSlowRTTSummary(sum slowRTTSummary) {
	attrs := []any{
		"window", sum.window,
		"suppressed", sum.suppressed,
		"worst_rtt", sum.worstD.Round(time.Millisecond),
		"worst_origin", sum.worst.source,
		"worst_endpoint", sum.worst.endpoint,
	}
	if sum.worst.target != "" {
		attrs = append(attrs, "worst_target", sum.worst.target)
	}
	log.Warn("[TRANSPORT] slow path RTT samples suppressed", attrs...)
}
