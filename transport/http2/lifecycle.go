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

// slotLifecycle 驱动每个槽位的健康评估与连接轮换。
type slotLifecycle struct {
	sched        *slotScheduler
	connLifetime time.Duration
	connMaxBytes int64

	// 为 nil 时禁用主动探测（未配置令牌）。
	probeFunc func(ctx context.Context, slot *transportSlot) (speedBps float64, verdict probeVerdict)

	slowRTT *slowRTTLogLimiter

	// 探测状态，仅由健康循环 goroutine 访问。
	probeUnsupported bool    // 服务端不提供 /v3/probe：回退为仅被动检测
	unsupportedCount int     // 已观察到的 unsupported 结论次数
	linkRefSpeed     float64 // 近期最佳探测速度（字节/秒）
	linkRefAt        time.Time

	// suspend 由健康循环与开流路径共享，只经 observeSuspend 访问："一次挂起只记账一次"
	// 因此是结构性保证，第二个采样者量到的区间里没有挂起。
	suspend suspendSampler
	// 识别到挂起时递增，健康循环据此重置吞吐基线：挂起期间的零吞吐不是降级证据。
	suspendEvents atomic.Int64
	// 健康循环已消费到的事件号，仅由该 goroutine 访问。
	samplingEpoch int64
}

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
			// 突发后没有新样本触发窗口滚动，被压掉的最后一批只能靠这里交代。
			lc.slowRTT.flushDue(time.Now())
		case <-ctx.Done():
			return
		}
	}
}

// suspendOrigin 必须由 time.Now() 产生：time.Time.Sub 只在两边都带单调读数时才走单调钟，
// 用零值会让 suspendOffset 恒为零，检测静默失效。
var suspendOrigin = time.Now()

// suspendOffset 返回一次采样的标量：墙钟 UnixNano 减相对 suspendOrigin 的单调读数。只存这一个
// 标量：分开存会在并发采样时撕裂出负离差。
func suspendOffset(now time.Time) int64 {
	return now.Round(0).UnixNano() - now.Sub(suspendOrigin).Nanoseconds()
}

// suspendBaselineUnset 取零值：真实的 suspendOffset 是 1e18 量级的正数，不会落到 0。
const suspendBaselineUnset = 0

// suspendSampler 用"墙钟推进 − 单调钟推进"的离差识别挂起：Go 的单调钟在系统睡眠、VM 暂停
// 时冻结，墙钟照走；用 ticker 的实到间隔测不到。判据有假阳性，调用方绝不能据此关闭连接。
type suspendSampler struct {
	baseline atomic.Int64
}

func (s *suspendSampler) sample(now time.Time) (divergence time.Duration, ok bool) {
	return s.sampleOffset(suspendOffset(now))
}

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

func (lc *slotLifecycle) observeSuspend(now time.Time) {
	divergence, ok := lc.suspend.sample(now)
	if !ok || divergence < sharedconfig.SuspendDivergenceThreshold {
		return
	}
	lc.suspendEvents.Add(1)
	lc.reportSuspend(divergence)
}

// 复用 lastHeavy 的语义：清零后下一次采样只重置基线、不产生结论。
func (lc *slotLifecycle) resetSamplingOnSuspend() {
	events := lc.suspendEvents.Load()
	if events == lc.samplingEpoch {
		return
	}
	lc.samplingEpoch = events

	for _, pool := range []*slotPool{lc.sched.priority, lc.sched.bulk} {
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

// 未配置探测令牌时不标记：没有复核手段却留下嫌疑，等于按嫌疑判死。
func (lc *slotLifecycle) reportSuspend(divergence time.Duration) {
	stats.RecordSuspendDetected()

	armed := lc.armSuspects()
	if armed == 0 {
		log.Debug("[TRANSPORT] suspend detected, no slot armed",
			"divergence", divergence.Round(time.Second))
		return
	}
	log.Info("[TRANSPORT] suspend detected, slots marked for reverify",
		"divergence", divergence.Round(time.Second),
		"suspects", armed)
}

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
			if s.connIdentity() != nil && !s.reverify.Swap(true) {
				armed++
			}
		}
	}
	return armed
}

func (lc *slotLifecycle) evaluate(interval time.Duration) {
	// 拥塞链路上每条连接都慢，标记或退役只会增加握手抖动，因此降级检测以健康的 RTT 为前提；
	// 轮换与 RTT 无关，始终执行。
	linkOK := stats.Collect().AvgRTT() <= sharedconfig.DegradedMaxRTT

	for _, pool := range []*slotPool{lc.sched.priority, lc.sched.bulk} {
		// shrink 和 retire 在写锁下交换删除槽位，遍历活跃区间必须持读锁。
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

func (lc *slotLifecycle) evaluateSlotHealth(idx int, s *transportSlot, interval time.Duration, linkOK bool) {
	if s.heavy.Load() == 0 {
		s.lastHeavy = 0
		s.suspected = false
		return
	}
	if s.lastHeavy == 0 {
		// 自空闲以来第一条 heavy 流：之前小流的字节数不得进入第一个样本。
		s.lastHeavy = 1
		s.lastBytes = s.bytesRecv.Load()
		s.lowCycles = 0
		s.recoverCycles = 0
		return
	}
	if !linkOK {
		// 低吞吐是链路属性而非连接损坏：推进基线并冻结计数器。
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
			s.degraded.Store(true)
			stats.RecordSlotDegraded()
			log.Info("[TRANSPORT] slot degraded", "slot", idx, "throughput_kb_s", throughput/1024)
		} else {
			s.suspected = true
		}
	}
}

func (lc *slotLifecycle) evaluateProbes(linkOK bool) {
	if !linkOK || lc.probeUnsupported || lc.probeFunc == nil {
		return
	}

	now := time.Now()
	probed := 0
	for _, pool := range []*slotPool{lc.sched.priority, lc.sched.bulk} {
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

// unsupported 累计两次才回退为仅被动检测：单次可能是服务端的瞬时故障。
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
		// 链路参考值是近期最佳吞吐量，只从 fast 探测刷新。
		if speed > lc.linkRefSpeed || now.Sub(lc.linkRefAt) > sharedconfig.ProbeLinkRefWindow {
			lc.linkRefSpeed = speed
			lc.linkRefAt = now
		}
	case probeSlow:
		// 链路参考值低于降级阈值说明整条链路才是瓶颈，归咎槽位只会徒增抖动。
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
	}
}

// 标记 expiring 后只在 idle 时收尾，绝不打断在飞流。
func (lc *slotLifecycle) evaluateRotation(idx int, s *transportSlot) {
	if s.expiring.Load() {
		if s.active.Load() == 0 {
			s.transport().CloseIdleConnections()
			s.expiring.Store(false)
			// 清零截止时间与字节数，否则 rotationDue 会因旧连接的状态每周期反复触发。
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

// 加 ±30% 抖动：同时拨号的槽位因此在不同周期过期，轮换与 TLS 握手不会聚成可被指纹
// 识别的突发。
func rotationLifetime(base time.Duration) time.Duration {
	span := int64(base) * 3 / 10
	if span <= 0 {
		return base
	}
	return base - time.Duration(span) + time.Duration(rand.Int64N(2*span+1))
}

func (lc *slotLifecycle) retire(idx int, s *transportSlot) {
	s.transport().CloseIdleConnections()
	if !lc.sched.remove(s) {
		return
	}
	stats.RecordSlotRetiredDegraded()
	log.Info("[TRANSPORT] slot retired (degraded)", "slot", idx)
}
