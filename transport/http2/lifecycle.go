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

	// 探测状态，仅由健康循环 goroutine 访问。
	probeUnsupported bool    // 服务端不提供 /v3/probe：回退为仅被动检测
	unsupportedCount int     // 已观察到的 unsupported 探测结论次数
	linkRefSpeed     float64 // 近期在该链路上观测到的最佳探测速度（字节/秒）
	linkRefAt        time.Time

	// suspend 是健康循环自己的挂起采样器：开流路径另有一份（http2Transport.suspend），
	// 两份各自维护基线、互不干扰。检测只由健康循环 goroutine 调用，因此这里不需要
	// 额外的并发纪律。
	suspend suspendSampler
	// suspendClaim 认领一次挂起：同一次挂起会被两个采样者各自独立观测到（开流路径
	// 上的采样甚至可能并发），只有认领者负责武装与记账，因此一次挂起恰好一条日志、
	// 一个计数。
	suspendClaim atomic.Bool
}

// run 驱动周期性的健康评估，直到 ctx 被取消。
func (lc *slotLifecycle) run(ctx context.Context) {
	interval := sharedconfig.HealthCheckInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			if divergence, ok := lc.suspend.observeNow(now); ok &&
				divergence >= sharedconfig.SuspendDivergenceThreshold {
				lc.onSuspend(divergence)
			}
			lc.evaluate(interval)
		case <-ctx.Done():
			return
		}
	}
}

// suspendSampler 通过"墙钟推进"与"单调钟推进"的离差识别进程被挂起（系统睡眠、
// VM 暂停、快照恢复）：Go 的单调时钟在这些状态下冻结（darwin 上就是
// mach_absolute_time，Apple 明确它不含睡眠时间），墙钟照走。
//
// 两个读数必须分别取样、分别保存：time.Time.Round(0) 剥掉单调读数，而未剥的
// Time 参与 Sub 时优先用单调读数——把同一次采样显式拆成两个标量，判据才是
// "墙钟差 − 单调差"。用 ticker 的实到间隔是测不到挂起的：挂起期间单调钟冻结，
// 定时器在自己的时间轴上并没有迟到。
//
// 两个标量都是原子量，因为开流路径上的采样是并发的（健康循环那份只有一个写入者，
// 但两者共用这个类型）。并发的采样者最坏会各自得出一次挂起结论——标记与记账都是
// 幂等的（见 slotLifecycle.reportSuspend）。
//
// 它只产生嫌疑：判据本身有假阳性（NTP/手动调时间向前跳、VM 快照恢复），
// 因此调用方只能用它标记槽位，绝不能据此关闭连接。
type suspendSampler struct {
	// base 把单调读数换算成可原子存储的标量（单调读数无法跨 Time 序列化）。
	// 构造后只读。
	base time.Time

	wall atomic.Int64 // 墙钟 UnixNano（已剥掉单调读数）
	mono atomic.Int64 // now.Sub(base) 的纳秒数
	set  atomic.Bool
}

// observeNow 用当前时刻采样一次。
func (s *suspendSampler) observeNow(now time.Time) (divergence time.Duration, ok bool) {
	return s.observe(now.Round(0).UnixNano(), now.Sub(s.base).Nanoseconds())
}

// observe 用两个标量读数推进采样器，返回"墙钟推进 − 单调钟推进"的离差。
// ok 为 false 表示这是首次采样（只建立基线，没有可比的上一次）。
func (s *suspendSampler) observe(wallNano, monoNano int64) (divergence time.Duration, ok bool) {
	prevWall, prevMono := s.wall.Load(), s.mono.Load()
	s.wall.Store(wallNano)
	s.mono.Store(monoNano)
	if !s.set.Swap(true) {
		return 0, false
	}
	return time.Duration(wallNano - prevWall - (monoNano - prevMono)), true
}

// onSuspend 供健康循环在识别到挂起后调用：重置健康采样基线，并尽力武装嫌疑槽位。
//
// 开流路径上的检测走 reportSuspend（见 http2Transport.maybeSuspend），它不碰
// 采样基线——lastHeavy 是健康循环 goroutine 的私有状态，别的 goroutine 无权
// 触摸。两条路各自独立观测到同一次挂起，记账由 reportSuspend 的认领合并成一次。
func (lc *slotLifecycle) onSuspend(divergence time.Duration) {
	lc.resetSampling()
	lc.reportSuspend(divergence)
}

// resetSampling 把健康采样的基线清零：挂起期间的"零吞吐"不是槽位变慢的证据，
// 把它喂给降级检测会让连接因为一次无效样本被退役。复用"自空闲以来第一条 heavy
// 流"的基线语义（lastHeavy 清零 ⇒ 下一次采样只重置基线、不产生结论）。
//
// 只允许健康循环 goroutine 调用。
func (lc *slotLifecycle) resetSampling() {
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

// reportSuspend 认领一次挂起并（尽力）武装嫌疑槽位：把承载连接的活跃槽位标记为
// "待复核"（见 transportSlot.reverify）。挂起期间底层连接可能已被中间设备静默
// 丢弃，而承载常驻流的槽位永远不会空闲，net/http 的空闲回收与 tooIdle 判定都
// 不会碰它；判死留给开流前的一次真实往返（http2Transport.reverifySlot）。
//
// 认领：同一次挂起会被健康循环与开流路径各自独立观测到（开流路径上的采样还可能
// 并发），只有认领者负责武装与记账，因此一次挂起恰好一条 Info、一个计数。
//
// 未配置探测令牌时没有复核手段（probeFunc 与判活探针同源于 ProbeToken），此时
// 不标记：把无法验证的启发式嫌疑留给开流路径，等于按嫌疑判死。
func (lc *slotLifecycle) reportSuspend(divergence time.Duration) {
	if !lc.suspendClaim.CompareAndSwap(false, true) {
		return // 这次挂起已由另一个采样者记账
	}
	defer lc.suspendClaim.Store(false)

	armed := lc.armSuspects()
	if armed == 0 {
		// 没有承载连接的槽位可标记，或没有判活手段（未配置探测令牌）。
		log.Debug("[TRANSPORT] suspend detected, no slot armed",
			"divergence", divergence.Round(time.Second))
		return
	}
	stats.RecordSuspendDetected()
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
