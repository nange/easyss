package http2

import (
	"sync"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// 慢路径 RTT 日志的配额：每个窗口最多直接打印 slowRTTLogQuota 条样本记录，
// 其余只计数，并在窗口结束时汇成一条汇总记录。链路整体变差时每个请求都会越界，
// 逐条打印只会把日志刷满；而"是哪些请求慢"的答案，在前几条样本加上汇总里那条
// 最慢的样本里已经够了。窗口滚动由下一条样本或健康循环的兜底冲刷驱动
// （见 slowRTTLogLimiter.flushDue），因此不会留下再也不打印的尾巴。
const (
	slowRTTLogWindow = 10 * time.Second
	slowRTTLogQuota  = 3
)

// 慢路径 RTT 样本的来源标识。
const (
	slowRTTSourceStream = "stream" // 代理请求的引导往返
	slowRTTSourceProbe  = "probe"  // 后台的主动探测
)

// slowRTTSample 描述一次路径 RTT 样本的来源，用于把慢样本归因到具体请求。
type slowRTTSample struct {
	// source 区分样本来自哪条路径（slowRTTSourceStream / slowRTTSourceProbe）。
	source string
	// endpoint 是请求的协议端点（/v3/tcp、/v3/udp、/v3/icmp、/v3/probe）。
	endpoint string
	// target 是请求的目标 "host:port"；探测没有目标，留空。
	target string
	// slot 是承载这次往返的连接槽位；nil（例如测试里裸构造的流）时省略
	// 槽位相关的属性。
	slot *transportSlot
}

// slowRTTLogLimiter 是慢路径 RTT 日志的限流器，每个传输层实例一个（因此状态
// 不会跨会话或跨用例串联）。
//
// 语义：窗口内前 quota 条越界样本逐条打印，此后的样本只计数并记住其中最慢的
// 一条；窗口结束时用一条汇总记录交代被压掉的数量与那条最慢样本。这样既保住
// 了"延迟突增时前几个越界请求是谁"这个最直接的信息，也保住了"这一窗口里被压
// 掉多少、最慢的是谁"这个量级信息。
type slowRTTLogLimiter struct {
	// window/quota 是配额参数，零值回落到包级默认值；用例可以构造更小的值来
	// 验证行为，而不必真的等 10 秒。
	window time.Duration
	quota  int

	mu         sync.Mutex
	windowEnd  time.Time // 当前窗口的结束时刻；零值表示还没有样本
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

// log 提交一次路径 RTT 样本：低于阈值直接丢弃，窗口内还有配额就逐条打印，
// 否则只记账。nil 接收者表示"未配置限流"（测试里裸构造的流与探测）：此时不做
// 限流，只按阈值打印——限流是日志噪声的策略问题，不该成为日志是否存在的开关。
func (l *slowRTTLogLimiter) log(d time.Duration, s slowRTTSample) {
	if d < sharedconfig.SlowRTTWarnThreshold {
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

	// 日志写在锁外：handler 会做一次文件/stdout 写入，不该让同一时刻落定的
	// 其他流的往返采样在锁上排队。
	if summary != nil {
		writeSlowRTTSummary(*summary)
	}
	if emit {
		writeSlowRTTSample(d, s)
	}
}

// flushDue 在窗口已结束时把被压掉的样本汇成一条记录；没有待汇总的内容时什么
// 也不做。健康循环每个周期调用一次——它是唯一一个不需要新样本就能发现"窗口
// 已经翻篇"的地方，因此突发结束后（没有新样本触发滚动）最后一批被压掉的样本
// 仍然会被交代出来。
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

// rollLocked 在窗口到期时开启新窗口，并返回上一窗口的汇总（没有压掉任何样本
// 时返回 nil）。窗口起点取第一个样本到来的时刻，因此空闲期不消耗配额。
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

// slowRTTSummary 是一个窗口内被配额压掉的慢样本的汇总。
type slowRTTSummary struct {
	window     time.Duration
	suppressed int
	worstD     time.Duration
	worst      slowRTTSample
}

// writeSlowRTTSample 打印一条慢样本记录，带上这次往返的身份：请求的
// endpoint/target、承载它的连接槽位、该槽位上的活跃流数与状态。托盘上的 RTT
// 是一个全局平均值——它只会告诉你"链路变慢了"，而排查需要的是"哪个请求慢"：
// 某个请求的引导往返真的变成了 800ms，还是后台探测自己慢，或是这条连接上正
// 压着别的流（heavy/expiring）。这些字段就是那个答案。
func writeSlowRTTSample(d time.Duration, s slowRTTSample) {
	attrs := []any{
		"rtt", d.Round(time.Millisecond),
		// 属性名是 origin 而不是 source：source 是 slog 的内建键，handler 会
		// 用它填入"文件:行号"（log.newReplaceAttrFunc 对它的值做 *slog.Source
		// 断言），同名属性会让默认 handler 在断言处 panic。
		"origin", s.source,
		"endpoint", s.endpoint,
		"proto", protoOfEndpoint(s.endpoint),
	}
	if s.target != "" {
		attrs = append(attrs, "target", s.target)
	}
	if s.slot != nil {
		// active 含本流自己（它在采样时仍然活跃），与传输层统计的口径一致。
		active := int(s.slot.active.Load())
		attrs = append(attrs,
			"slot", s.slot.idx,
			"slot_state", slotStatus(s.slot, active),
			"active_streams", active)
	}
	log.Warn("[TRANSPORT] slow path RTT sample", attrs...)
}

// writeSlowRTTSummary 打印配额汇总记录：这一窗口里有多少条越界样本被压掉，
// 以及其中越界最狠的那一条是谁。汇总里的槽位属性被刻意省略——它是采样时刻的
// 状态，留到窗口结束时再打印只会误导。
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
