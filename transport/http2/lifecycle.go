package http2

import (
	"context"
	"math/rand/v2"
	"sync/atomic"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// slotLifecycle 负责每个槽位的连接生命周期：一个健康循环采样下载吞吐量以判断
// 降级嫌疑，并通过槽位自身连接上的主动探测加以确认；此外在超过生命周期或字节
// 限制后执行连接轮换。它复用调度器的池管理来退役空闲的降级槽位。
type slotLifecycle struct {
	sched        *slotScheduler
	connLifetime time.Duration // 连接轮换前的最大存活时长
	connMaxBytes int64         // 每条连接轮换前的最大字节数

	// probeFunc 主动测量某个槽位连接的吞吐量；为 nil 时禁用探测
	// （未配置探测令牌）。
	probeFunc func(ctx context.Context, slot *transportSlot) (speedBps float64, verdict probeVerdict)

	// slowRTT 是慢路径 RTT 日志的限流器（与传输层、探测共用同一个实例）；
	// 健康循环只用它做窗口过后的兜底冲刷（见 slowRTTLogLimiter.flushDue）。
	slowRTT *slowRTTLogLimiter

	// 探测状态，仅由健康循环 goroutine 访问。
	probeUnsupported bool    // 服务端不提供 /v3/probe：回退为仅被动检测
	unsupportedCount int     // 已观察到的 unsupported 探测结论次数
	linkRefSpeed     float64 // 近期在该链路上观测到的最佳探测速度（字节/秒）
	linkRefAt        time.Time

	// suspend 是健康循环与开流路径**共享**的挂起采样器：挂起后的第一个观测者
	// 可能是任何一个（实测开流路径更早，见 http2Transport.maybeSuspend）。共享
	// 一条基线是"一次挂起只记账一次"的结构性保证——第二个采样者量到的是"基线与
	// 自己之间"，那一段里没有挂起。它只由 observeSuspend 访问。
	suspend suspendSampler
	// suspendEvents 在每次识别到挂起时递增。健康循环据此重置自己的吞吐采样基线：
	// 挂起期间没有吞吐，那一段样本不是降级证据，而"是谁先发现的挂起"与采样基线的
	// 归属无关（基线是健康循环 goroutine 的私有状态）。
	suspendEvents atomic.Int64
	// samplingEpoch 是健康循环已消费到的事件号，仅由该 goroutine 访问。
	samplingEpoch int64
}

// run 驱动周期性的健康评估，直到 ctx 被取消。
func (lc *slotLifecycle) run(ctx context.Context) {
	interval := sharedconfig.HealthCheckInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			lc.observeSuspend(time.Now())
			lc.resetSamplingOnSuspend()
			lc.evaluate(interval)
			// 慢路径 RTT 的配额汇总兜底：突发结束后不再有新样本触发窗口滚动，
			// 被配额压掉的最后一批样本只能由这个周期性的观察者交代出来。
			lc.slowRTT.flushDue(time.Now())
		case <-ctx.Done():
			return
		}
	}
}

// suspendOrigin 把单调读数换算成可存储的标量。它必须由 time.Now() 产生：
// time.Time.Sub 只在两边都带单调读数时才走单调钟，用零值会让"单调读数"退化成
// 墙钟，进而让下面那个差恒为零、检测静默失效。进程内只读。
var suspendOrigin = time.Now()

// suspendOffset 返回一次采样的标量：墙钟 UnixNano 减去单调读数（相对
// suspendOrigin）。机器醒着时它恒定（两个钟同速前进），挂起一次它恰好跳过睡眠
// 的时长，因此"相邻两次采样的差"就是墙钟与单调钟的离差本身。
//
// 把两个读数压成一个标量，存储就只需要一个 atomic.Int64：分别存两个标量会在
// 并发采样时撕裂（读者可能拿到"新墙钟 + 旧单调钟"，算出的离差是负的，即假阴性），
// 而这个差值天然是不可分割的一次采样。
func suspendOffset(now time.Time) int64 {
	return now.Round(0).UnixNano() - now.Sub(suspendOrigin).Nanoseconds()
}

// suspendBaselineUnset 是"还没采样过"的基线哨兵，取零值：真实的 suspendOffset 是
// 1.7e18 量级的正数（当前墙钟 UnixNano 减去进程内的单调读数），永远不会落到 0，
// 因此零值即"未采样"，采样器不需要任何初始化纪律。
const suspendBaselineUnset = 0

// suspendSampler 通过"墙钟推进"与"单调钟推进"的离差识别进程被挂起（系统睡眠、
// VM 暂停、快照恢复）：Go 的单调时钟在这些状态下冻结（darwin 上就是
// mach_absolute_time，Apple 明确它不含睡眠时间），墙钟照走。
//
// 用 ticker 的实到间隔是测不到挂起的：挂起期间单调钟冻结，定时器在自己的时间轴
// 上并没有迟到；判据只能是"墙钟差 − 单调差"，也就是下面那个 offset 的增量。
//
// 采样器由健康循环与开流路径共享（见 slotLifecycle.suspend），一次采样就是一次
// 消费：CAS 既推进基线又认领这次观测，因此并发采样者里只有一个赢家能拿到真实
// 离差，其余重读基线后量到的是"两次采样之间"的小量——一次挂起恰好一个观测者。
//
// 它只产生嫌疑：判据本身有假阳性（NTP/手动调时间向前跳、VM 快照恢复），
// 因此调用方只能用它标记槽位，绝不能据此关闭连接。
type suspendSampler struct {
	baseline atomic.Int64
}

// sample 用当前时刻采样一次：返回与上一次采样的离差。ok 为 false 表示这是首次
// 采样（只建立基线，没有可比的上一次）。
func (s *suspendSampler) sample(now time.Time) (divergence time.Duration, ok bool) {
	return s.sampleOffset(suspendOffset(now))
}

// sampleOffset 是 sample 的纯标量形式（测试用它直接构造"睡了一觉"的基线）。
func (s *suspendSampler) sampleOffset(offset int64) (divergence time.Duration, ok bool) {
	for {
		prev := s.baseline.Load()
		if prev == suspendBaselineUnset {
			if s.baseline.CompareAndSwap(prev, offset) {
				return 0, false
			}
			continue
		}
		if !s.baseline.CompareAndSwap(prev, offset) {
			continue // 另一个采样者先认领了这次推进
		}
		return time.Duration(offset - prev), true
	}
}

// observeSuspend 采样一次挂起判据；识别到挂起时递增事件号、（尽力）武装嫌疑槽位
// 并记账。健康循环与开流路径都调用它，两者共享同一条采样基线（见
// slotLifecycle.suspend），因此同一次挂起只会有第一个采样者拿到真实离差：既不会
// 重复记账，也不会在事后把已经复核过的槽位重新武装。
func (lc *slotLifecycle) observeSuspend(now time.Time) {
	divergence, ok := lc.suspend.sample(now)
	if !ok || divergence < sharedconfig.SuspendDivergenceThreshold {
		return
	}
	lc.suspendEvents.Add(1)
	lc.reportSuspend(divergence)
}

// resetSamplingOnSuspend 消费挂起事件号：自上次调用以来发生过挂起（不论是谁发现的）
// 就重置健康采样的基线。挂起期间的"零吞吐"不是槽位变慢的证据，把它喂给降级检测会
// 让连接因为一次无效样本被退役。复用"自空闲以来第一条 heavy 流"的基线语义
// （lastHeavy 清零 ⇒ 下一次采样只重置基线、不产生结论）。
//
// 只允许健康循环 goroutine 调用（samplingEpoch 与 lastHeavy 都是它的私有状态）。
func (lc *slotLifecycle) resetSamplingOnSuspend() {
	events := lc.suspendEvents.Load()
	if events == lc.samplingEpoch {
		return
	}
	lc.samplingEpoch = events

	for _, pool := range []*slotPool{lc.sched.priority, lc.sched.bulk} {
		// 与 evaluate 相同的快照纪律：活跃区间可能被 shrink/retire 在写锁下
		// 交换修改。
		lc.sched.mu.RLock()
		live := int(pool.liveCount.Load())
		slots := make([]*transportSlot, live)
		copy(slots, pool.slots[:live])
		lc.sched.mu.RUnlock()

		for _, s := range slots {
			s.lastHeavy = 0
		}
	}
}

// reportSuspend （尽力）武装嫌疑槽位并记账：把承载连接的活跃槽位标记为"待复核"
// （见 transportSlot.reverify）。挂起期间底层连接可能已被中间设备静默丢弃，而承载
// 常驻流的槽位永远不会空闲，net/http 的空闲回收与 tooIdle 判定都不会碰它；判死
// 留给开流前的一次真实往返（http2Transport.reverifySlot）。
//
// 它由 observeSuspend 在拿到真实离差后调用，而那是每次挂起唯一的观测者（见
// suspendSampler 的 CAS 消费），因此"每次挂起恰好一次计数"是结构性保证，不靠
// 这里的 armed 兜底：armed 只决定要不要记一条 Info（没有承载连接的槽位、或没有
// 判活手段时只记 Debug），计数照记——"这台上挂起过几次"与"当时有没有连接可标记"
// 是两件事。
//
// 未配置探测令牌时没有复核手段（probeFunc 与判活探针同源于 ProbeToken），此时
// 不标记：把无法验证的启发式嫌疑留给开流路径，等于按嫌疑判死。
func (lc *slotLifecycle) reportSuspend(divergence time.Duration) {
	stats.RecordSuspendDetected()

	armed := lc.armSuspects()
	if armed == 0 {
		// 没有承载连接的槽位可标记，或没有判活手段（未配置探测令牌）。
		log.Debug("[TRANSPORT] suspend detected, no slot armed",
			"divergence", divergence.Round(time.Second))
		return
	}
	log.Info("[TRANSPORT] suspend detected, slots marked for reverify",
		"divergence", divergence.Round(time.Second),
		"suspects", armed)
}

// armSuspects 把所有承载连接的活跃槽位标记为"待复核"（见 transportSlot.reverify），
// 返回本次新标记的数量。它只做原子写，因此健康循环与开流路径可以并发调用；重复
// 调用是幂等的，新标记数为 0 说明没有可标记的连接，或这次挂起已被标记过。
func (lc *slotLifecycle) armSuspects() (armed int) {
	if lc.probeFunc == nil {
		return 0
	}
	for _, pool := range []*slotPool{lc.sched.priority, lc.sched.bulk} {
		lc.sched.mu.RLock()
		live := int(pool.liveCount.Load())
		slots := make([]*transportSlot, live)
		copy(slots, pool.slots[:live])
		lc.sched.mu.RUnlock()

		for _, s := range slots {
			if s.conn.Load() != nil && !s.reverify.Swap(true) {
				armed++
			}
		}
	}
	return armed
}

// evaluate 遍历两个池的活跃槽位：下载吞吐量输入降级嫌疑检测器，主动探测确认
// 嫌疑，连接时长/字节数输入轮换判断，空闲的降级槽位会被退役。
func (lc *slotLifecycle) evaluate(interval time.Duration) {
	// 拥塞链路（高 RTT）会让每条连接都变慢：此时标记或退役槽位只会增加
	// 握手抖动而没有任何收益，因此降级检测以健康的 RTT 为前提。而轮换
	// 恰恰是受限连接所需要的，与 RTT 无关，始终执行。
	linkOK := stats.Collect().AvgRTT() <= sharedconfig.DegradedMaxRTT

	for _, pool := range []*slotPool{lc.sched.priority, lc.sched.bulk} {
		// 在调度器读锁下快照活跃槽位：shrink 和 retire 在写锁下交换删除
		// 槽位，因此不加锁地遍历活跃区间会与这些交换产生竞争。
		lc.sched.mu.RLock()
		live := int(pool.liveCount.Load())
		slots := make([]*transportSlot, live)
		copy(slots, pool.slots[:live])
		lc.sched.mu.RUnlock()

		for i, s := range slots {
			lc.evaluateSlotHealth(i, s, interval, linkOK)
			lc.evaluateRotation(i, s)
			if linkOK && s.degraded.Load() && s.active.Load() == 0 {
				lc.retire(i, s)
			}
		}
	}

	lc.evaluateProbes(linkOK)
}

// evaluateSlotHealth 根据槽位近期的下载吞吐量更新其嫌疑状态。只考虑承载 heavy
// 流的槽位——空闲或短命的槽位天然承载零吞吐量。当主动探测开启时（服务端提供
// /v3/probe），持续低吞吐量只把槽位标记为 suspected，由主动探测确认或否定；
// 未开启探测时（服务端不支持，或未配置探测令牌），嫌疑直接标记槽位为 degraded
// （旧行为）。两种模式下，经过 DegradedRecoverCycles 个健康周期后标记都会被
// 清除。
func (lc *slotLifecycle) evaluateSlotHealth(idx int, s *transportSlot, interval time.Duration, linkOK bool) {
	if s.heavy.Load() == 0 {
		s.lastHeavy = 0
		s.suspected = false
		return
	}
	if s.lastHeavy == 0 {
		// 该槽位自空闲以来第一条 heavy 流：之前小流传输的字节数不得影响
		// 第一个样本，因此重置基线并跳过本次周期。
		s.lastHeavy = 1
		s.lastBytes = s.bytesRecv.Load()
		s.lowCycles = 0
		s.recoverCycles = 0
		return
	}
	if !linkOK {
		// 链路拥塞：低吞吐量是链路属性，而不是这条连接损坏的证据。
		// 推进基线，使第一个健康周期从干净的样本开始，并冻结计数器。
		s.lastBytes = s.bytesRecv.Load()
		return
	}

	now := s.bytesRecv.Load()
	perSec := int64(interval / time.Second)
	if perSec <= 0 {
		perSec = 1
	}
	throughput := (now - s.lastBytes) / perSec
	s.lastBytes = now

	if throughput >= int64(sharedconfig.DegradedThroughputThreshold) {
		s.lowCycles = 0
		s.suspected = false
		if s.degraded.Load() {
			s.recoverCycles++
			if s.recoverCycles >= sharedconfig.DegradedRecoverCycles {
				s.degraded.Store(false)
				s.recoverCycles = 0
				log.Info("[TRANSPORT] slot recovered", "slot", idx, "throughput_kb_s", throughput/1024)
			}
		}
		return
	}

	s.recoverCycles = 0
	s.lowCycles++
	if s.lowCycles >= sharedconfig.DegradedPersistCycles && !s.degraded.Load() {
		s.lowCycles = 0
		if lc.probeUnsupported || lc.probeFunc == nil {
			// 没有主动探测（服务端不提供 /v3/probe，或未配置探测令牌）：
			// 被动采样器直接把槽位标记为 degraded，与探测功能出现之前一致。
			s.degraded.Store(true)
			stats.RecordSlotDegraded()
			log.Info("[TRANSPORT] slot degraded", "slot", idx, "throughput_kb_s", throughput/1024)
		} else {
			s.suspected = true
		}
	}
}

// evaluateProbes 用主动探测确认降级嫌疑。只探测被动采样器标记为 suspected 的
// 槽位，且仅在链路 RTT 健康时进行（拥塞链路会让每次探测都变慢）。每个周期
// 最多探测 ProbeMaxPerInterval 个槽位；每个槽位在 ProbeCooldown 内最多
// 重新探测一次。
func (lc *slotLifecycle) evaluateProbes(linkOK bool) {
	if !linkOK || lc.probeUnsupported || lc.probeFunc == nil {
		return
	}

	now := time.Now()
	probed := 0
	for _, pool := range []*slotPool{lc.sched.priority, lc.sched.bulk} {
		// 与 evaluate 相同的快照纪律：活跃区间可能被 shrink/retire 在写锁下
		// 交换修改。
		lc.sched.mu.RLock()
		live := int(pool.liveCount.Load())
		slots := make([]*transportSlot, live)
		copy(slots, pool.slots[:live])
		lc.sched.mu.RUnlock()

		for i := 0; i < len(slots) && probed < sharedconfig.ProbeMaxPerInterval; i++ {
			s := slots[i]
			if !s.suspected || s.degraded.Load() {
				continue
			}
			if now.Sub(s.lastProbeAt) < sharedconfig.ProbeCooldown {
				continue
			}
			lc.probeSlot(i, s, now)
			probed++
		}
	}
}

// probeSlot 执行一次探测并把结论并入槽位的 degraded 状态：
//   - slow：连续 ProbeConfirmCycles 次慢探测后确认降级——除非链路参考速度
//     表明整条链路才是瓶颈，此时不应归咎于该槽位；
//   - fast：连接健康（流量慢是源端或流本身的属性，而不是连接属性）；清除嫌疑；
//   - inconclusive：状态不变；
//   - unsupported：累计两次该结论后，服务端被视为不提供探测端点，
//     检测回退为仅被动模式。
func (lc *slotLifecycle) probeSlot(idx int, s *transportSlot, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), sharedconfig.ProbeTimeout)
	defer cancel()

	speed, verdict := lc.probeFunc(ctx, s)
	s.lastProbeAt = now
	stats.RecordSlotProbe()

	switch verdict {
	case probeFast:
		s.probeLowCycles = 0
		s.suspected = false
		// 链路参考值是这条链路近期达到的最佳吞吐量；只从 fast 探测刷新。
		if speed > lc.linkRefSpeed || now.Sub(lc.linkRefAt) > sharedconfig.ProbeLinkRefWindow {
			lc.linkRefSpeed = speed
			lc.linkRefAt = now
		}
	case probeSlow:
		// 新鲜的链路参考值低于降级阈值，说明此刻整条链路就是瓶颈：
		// 每条连接都慢，归咎于这个槽位只会徒增握手抖动。
		if now.Sub(lc.linkRefAt) <= sharedconfig.ProbeLinkRefWindow &&
			lc.linkRefSpeed < float64(sharedconfig.DegradedThroughputThreshold) {
			s.probeLowCycles = 0
			s.suspected = false
			return
		}
		stats.RecordSlotProbeSlow()
		s.probeLowCycles++
		if s.probeLowCycles >= sharedconfig.ProbeConfirmCycles {
			s.probeLowCycles = 0
			s.suspected = false
			s.degraded.Store(true)
			stats.RecordSlotDegraded()
			log.Info("[TRANSPORT] slot degraded", "slot", idx, "probe_kb_s", int64(speed)/1024)
		}
	case probeUnsupported:
		lc.unsupportedCount++
		if lc.unsupportedCount >= 2 {
			lc.probeUnsupported = true
			stats.RecordSlotProbeUnsupported()
			log.Info("[TRANSPORT] server does not serve /v3/probe, falling back to passive detection")
		}
	case probeInconclusive:
		// 连接已死（由流错误和轮换处理）或临时性拒绝（429）：保持当前状态，
		// 冷却期过后重新探测。
	}
}

// evaluateRotation 在槽位连接超过生命周期或字节限制后把它标记为 expiring，
// 并在槽位空闲时完成轮换：关闭疲惫的连接，使下一条流拨号建立新连接。
// 进行中的流永远不会被打断。
func (lc *slotLifecycle) evaluateRotation(idx int, s *transportSlot) {
	if s.expiring.Load() {
		if s.active.Load() == 0 {
			s.t.CloseIdleConnections()
			s.expiring.Store(false)
			// 疲惫的连接已被回收：把截止时间和字节数清零，使 rotationDue
			// 不会因旧连接的状态再次触发——否则连接已被关闭（空闲超时、
			// 服务端关闭）的槽位会在每个健康周期都被标记为 expiring，
			// 直到下次拨号通过 resetConn 重置状态。下一条流会拨号建立
			// 新连接并开启新的生命周期。
			s.expireAt.Store(0)
			s.connBytes.Store(0)
			stats.RecordConnRotated()
			log.Info("[TRANSPORT] connection rotated", "slot", idx)
		}
		return
	}
	if lc.rotationDue(s, time.Now()) {
		s.expiring.Store(true)
		log.Info("[TRANSPORT] slot connection expiring", "slot", idx)
	}
}

// rotationDue 报告槽位连接是否超过生命周期或字节限制、应停止接收新流。
// 字节限制统计双向流量。
func (lc *slotLifecycle) rotationDue(s *transportSlot, now time.Time) bool {
	if lc.connLifetime > 0 {
		if expireAt := s.expireAt.Load(); expireAt > 0 && now.UnixNano() >= expireAt {
			return true
		}
	}
	if lc.connMaxBytes > 0 && s.connBytes.Load() >= lc.connMaxBytes {
		return true
	}
	return false
}

// rotationLifetime 返回带每连接对称随机抖动 ±30% 的连接生命周期
// （落在 [0.7×base, 1.3×base] 内）。同一突发中创建的连接（例如多个槽位
// 同时拨号）随后会在不同的健康周期过期，这样轮换及其后的 TLS 握手不会
// 聚集成一个可被指纹识别的突发。抖动围绕配置的生命周期对称，因此均值保持
// 在 base（默认 12 × timeout = 6 分钟），而同一批连接的超时散布在 3.6 分钟的窗口内
// （大约 43 个健康周期）——没有长尾，整批也不会同时进入 expiring，
// 始终有健康槽位可供新流分散承载。
func rotationLifetime(base time.Duration) time.Duration {
	span := int64(base) * 3 / 10
	if span <= 0 {
		return base
	}
	return base - time.Duration(span) + time.Duration(rand.Int64N(2*span+1))
}

// retire 关闭降级槽位的空闲连接，并在槽位不再承载任何流时把它从活跃集合中
// 移除。
func (lc *slotLifecycle) retire(idx int, s *transportSlot) {
	s.t.CloseIdleConnections()
	if !lc.sched.remove(s) {
		return
	}
	stats.RecordSlotRetiredDegraded()
	log.Info("[TRANSPORT] slot retired (degraded)", "slot", idx)
}
