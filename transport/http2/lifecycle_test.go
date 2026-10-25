package http2

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
)

func TestEvaluateSlotHealth(t *testing.T) {
	interval := config.HealthCheckInterval
	// 传统模式（probeUnsupported）：被动采样器直接标记 degraded，
	// 与探测功能出现之前的行为一致。
	lc := &slotLifecycle{probeUnsupported: true}

	newHeavySlot := func() *transportSlot {
		s := slotWithPool(&http.Transport{})
		s.heavy.Store(1)
		return s
	}
	// lowThroughput 模拟一个健康周期内只传输 10KB
	// （2KB/s，远低于 degraded 吞吐阈值）。
	lowThroughput := func(s *transportSlot) {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}
	highThroughput := func(s *transportSlot) {
		s.bytesRecv.Add(2 * 1024 * 1024) // 5 秒内 2MB = 400KB/s
		lc.evaluateSlotHealth(0, s, interval, true)
	}

	t.Run("marks degraded after consecutive slow intervals", func(t *testing.T) {
		s := newHeavySlot()
		// heavy 0->1 后的首个周期只重置吞吐基线，被跳过。
		lowThroughput(s)
		for i := range config.DegradedPersistCycles - 1 {
			lowThroughput(s)
			if s.degraded.Load() {
				t.Fatalf("degraded too early at cycle %d", i+1)
			}
		}
		lowThroughput(s)
		if !s.degraded.Load() {
			t.Fatal("expected degraded after persist cycles")
		}
	})

	t.Run("healthy interval resets the slow counter", func(t *testing.T) {
		s := newHeavySlot()
		lowThroughput(s) // 基线重置
		lowThroughput(s)
		lowThroughput(s)
		highThroughput(s)
		lowThroughput(s)
		lowThroughput(s)
		if s.degraded.Load() {
			t.Fatal("expected not degraded after a healthy interval")
		}
	})

	t.Run("clears degraded after consecutive healthy intervals", func(t *testing.T) {
		s := newHeavySlot()
		lowThroughput(s) // 基线重置
		for range config.DegradedPersistCycles {
			lowThroughput(s)
		}
		if !s.degraded.Load() {
			t.Fatal("expected degraded")
		}
		highThroughput(s)
		if !s.degraded.Load() {
			t.Fatal("cleared too early after a single healthy interval")
		}
		highThroughput(s)
		if s.degraded.Load() {
			t.Fatal("expected cleared after recover cycles")
		}
	})

	t.Run("slots without heavy streams never degrade", func(t *testing.T) {
		s := slotWithPool(&http.Transport{})
		for range config.DegradedPersistCycles + 2 {
			lowThroughput(s)
		}
		if s.degraded.Load() {
			t.Fatal("non-heavy slot must not degrade")
		}
	})

	t.Run("congested link never degrades", func(t *testing.T) {
		s := newHeavySlot()
		// 基线重置发生在拥塞闸门之前。
		lc.evaluateSlotHealth(0, s, interval, false)
		for range config.DegradedPersistCycles + 2 {
			s.bytesRecv.Add(10 * 1024)
			lc.evaluateSlotHealth(0, s, interval, false)
		}
		if s.degraded.Load() {
			t.Fatal("degraded while link congested")
		}
	})

	t.Run("heavy 0->1 transition resets throughput baseline", func(t *testing.T) {
		s := newHeavySlot()
		s.bytesRecv.Add(50 * 1024) // 更早的小流留下的陈旧字节
		// 首个样本只重置基线。
		lc.evaluateSlotHealth(0, s, interval, true)
		if s.lowCycles != 0 {
			t.Fatalf("lowCycles = %d after baseline reset, want 0", s.lowCycles)
		}
		// 随后的慢周期从重置点开始计数。
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
		if s.lowCycles != 1 {
			t.Fatalf("lowCycles = %d, want 1", s.lowCycles)
		}
	})
}

// newTestLifecycle 在 n 个存活槽位上构建生命周期，并给定探测函数（nil 表示禁用探测）。
// 全部 n 个槽位都位于 priority 池（bulk 池保持为空），因此测试以 priority.slots[i] 访问它们。
// 槽位带占位连接身份（探测在这一代无连接时不拨号）；无连接的情形见 TestProbeSkippedWithoutConnection。
func newTestLifecycle(n int, probe func(context.Context, *transportSlot) (float64, probeVerdict)) (*slotLifecycle, *slotScheduler) {
	slots := make([]*transportSlot, n)
	for i := range slots {
		slots[i] = probeSlotWithPool(&http.Transport{})
	}
	sch := &slotScheduler{
		priority: &slotPool{
			slots:    slots,
			maxSlots: n,
			base:     8,
		},
		bulk: &slotPool{
			slots:    []*transportSlot{probeSlotWithPool(&http.Transport{})},
			maxSlots: 1,
			base:     16,
		},
	}
	sch.priority.liveCount.Store(int32(n))
	lc := &slotLifecycle{sched: sch, probeFunc: probe}
	return lc, sch
}

func TestSuspicionInsteadOfDirectMark(t *testing.T) {
	interval := config.HealthCheckInterval
	// 探测模式：配置了探测函数，因此被动低速只产生嫌疑；
	// degraded 标记由探测确认。（这里的假探测函数不会被调用——
	// 只有被动采样器在运行。）
	lc := &slotLifecycle{probeFunc: func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeInconclusive
	}}
	s := slotWithPool(&http.Transport{})
	s.heavy.Store(1)

	low := func() {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}
	high := func() {
		s.bytesRecv.Add(2 * 1024 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}

	low() // 基线重置
	for range config.DegradedPersistCycles {
		low()
	}
	if s.degraded.Load() {
		t.Fatal("probe mode must not mark degraded directly")
	}
	if !s.suspected {
		t.Fatal("expected suspicion after persistent low throughput")
	}

	// 一个健康周期无需任何探测即可清除嫌疑。
	high()
	if s.suspected {
		t.Fatal("expected suspicion cleared by healthy throughput")
	}
}

func TestNoProbeFuncFallsBackToPassive(t *testing.T) {
	interval := config.HealthCheckInterval
	// 未配置探测函数（例如没有探测令牌）：被动采样器保持传统的直接标记。
	lc := &slotLifecycle{}
	s := slotWithPool(&http.Transport{})
	s.heavy.Store(1)

	lc.evaluateSlotHealth(0, s, interval, true) // 基线重置
	for range config.DegradedPersistCycles {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}
	if !s.degraded.Load() {
		t.Fatal("expected legacy degraded marking without a probe function")
	}
	if s.suspected {
		t.Fatal("legacy mode must not set suspicion")
	}
}

func TestProbeConfirmDegraded(t *testing.T) {
	lc, sch := newTestLifecycle(2, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 10 * 1024, probeSlow // 10KB/s，远低于 64KB/s
	})
	s := sch.priority.slots[0]
	s.suspected = true

	lc.evaluateProbes(true)
	if s.degraded.Load() {
		t.Fatal("degraded after a single slow probe")
	}
	if s.probeLowCycles != 1 {
		t.Fatalf("probeLowCycles = %d, want 1", s.probeLowCycles)
	}

	s.lastProbeAt = time.Time{} // 绕过冷却
	lc.evaluateProbes(true)
	if !s.degraded.Load() {
		t.Fatal("expected degraded after ProbeConfirmCycles slow probes")
	}
	if s.suspected {
		t.Fatal("expected suspicion cleared once degraded")
	}
}

func TestProbeFastClearsSuspicion(t *testing.T) {
	const fastSpeed = 10 * 1024 * 1024 // 10MB/s
	calls := 0
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return fastSpeed, probeFast
	})
	s := sch.priority.slots[0]
	s.suspected = true

	lc.evaluateProbes(true)

	if calls != 1 {
		t.Fatalf("probe calls = %d, want 1", calls)
	}
	if s.suspected {
		t.Fatal("fast probe must clear suspicion")
	}
	if s.degraded.Load() {
		t.Fatal("fast probe must not mark degraded")
	}
}

// 探测进行中换代：结论属于旧连接，必须丢弃，不能把旧连接的快判决记到新连接头上。
func TestProbeResultDroppedWhenConnectionChangesDuringProbe(t *testing.T) {
	lc, sch := newTestLifecycle(1, nil)
	s := sch.priority.slots[0]
	lc.probeFunc = func(context.Context, *transportSlot) (float64, probeVerdict) {
		s.gen.Store(&slotTransport{slot: s, tr: &http.Transport{}})
		attachConn(s, &countingConn{})
		return 10 * 1024 * 1024, probeFast
	}
	s.suspected = true
	s.probeBackoff = 2

	lc.evaluateProbes(true)

	if s.suspected || s.probeBackoff != 0 || s.probeConn != nil ||
		!s.probeHoldUntil.IsZero() || !s.lastProbeAt.IsZero() {
		t.Fatalf("verdict applied across a connection swap: suspected=%v backoff=%d hold=%v lastProbe=%v",
			s.suspected, s.probeBackoff, s.probeHoldUntil, s.lastProbeAt)
	}
}

// 已知例外（服务端流上限时 net/http 在同一代再拨一条）同样只是换了连接身份：快判决不能记到
// 新连接头上，否则可能用新连接的快清掉旧连接的嫌疑。
func TestProbeResultDroppedWhenSecondConnDialedIntoGeneration(t *testing.T) {
	lc, sch := newTestLifecycle(1, nil)
	s := sch.priority.slots[0]
	lc.probeFunc = func(context.Context, *transportSlot) (float64, probeVerdict) {
		// 代不变，只把同一代的连接身份换成新拨的那条（ErrNoCachedConn 路径）。
		attachConn(s, &countingConn{})
		return 10 * 1024 * 1024, probeFast
	}
	s.suspected = true
	s.probeBackoff = 2

	lc.evaluateProbes(true)

	if s.suspected || s.probeBackoff != 0 || s.probeConn != nil ||
		!s.probeHoldUntil.IsZero() || !s.lastProbeAt.IsZero() {
		t.Fatalf("verdict applied across a same-generation dial: suspected=%v backoff=%d hold=%v lastProbe=%v",
			s.suspected, s.probeBackoff, s.probeHoldUntil, s.lastProbeAt)
	}
}

// 探测判定连接无责后，被动低速在静默期内不得再次起疑：慢源站会稳定复现，否则同一槽位会按
// ProbeCooldown 的节拍无限重探。
func TestProbeHoldOffResuspicion(t *testing.T) {
	interval := config.HealthCheckInterval
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 10 * 1024 * 1024, probeFast
	})
	s := sch.priority.slots[0]
	s.heavy.Store(1)

	low := func() {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}

	low() // 基线重置
	for range config.DegradedPersistCycles {
		low()
	}
	if !s.suspected {
		t.Fatal("expected suspicion before the probe")
	}

	lc.evaluateProbes(true)
	if s.suspected {
		t.Fatal("fast probe must clear suspicion")
	}

	for range config.DegradedPersistCycles + 1 {
		low()
	}
	if s.suspected {
		t.Fatal("slow throughput inside the hold must not re-arm suspicion")
	}

	s.probeHoldUntil = time.Now().Add(-time.Second)
	for range config.DegradedPersistCycles {
		low()
	}
	if !s.suspected {
		t.Fatal("expected suspicion once the hold expired")
	}
}

// 探测状态属于某一条连接：连接在两次健康周期之间被换掉并立刻重拨时，健康循环看不到
// "这一代无连接"的窗口，旧连接的嫌疑、退避与静默期都不得作用到新连接。
func TestProbeStateDroppedOnConnectionReplacement(t *testing.T) {
	interval := config.HealthCheckInterval
	calls := 0
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return 10 * 1024 * 1024, probeFast
	})
	s := sch.priority.slots[0]
	s.heavy.Store(1)
	s.suspected = true
	s.probeConn = s.connIdentity()
	s.probeBackoff = 6
	s.probeHoldUntil = time.Now().Add(config.ProbeHoldWindow)
	s.lastProbeAt = time.Now()

	// 旧连接被回收（换代），下一个开流立刻重拨。
	s.gen.Store(&slotTransport{slot: s, tr: &http.Transport{}})
	attachConn(s, &countingConn{})

	lc.evaluateSlotHealth(0, s, interval, true)
	lc.evaluateProbes(true)
	if s.suspected || s.probeBackoff != 0 || !s.probeHoldUntil.IsZero() || calls != 0 {
		t.Fatalf("stale probe state survived the replacement: suspected=%v backoff=%d hold=%v calls=%d",
			s.suspected, s.probeBackoff, s.probeHoldUntil, calls)
	}

	// 新连接重新积累低速周期后必须从基础冷却开始，而不是继承旧连接的退避。
	low := func() {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}
	for range config.DegradedPersistCycles {
		low()
	}
	if !s.suspected {
		t.Fatal("expected suspicion to re-arm on the replacement connection")
	}
	lc.evaluateProbes(true)
	if calls != 1 {
		t.Fatalf("probe calls = %d, want 1: the replacement must not inherit the old cooldown", calls)
	}
}

func TestProbeUnsupportedFallsBackToPassive(t *testing.T) {
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeUnsupported
	})
	s := sch.priority.slots[0]
	s.suspected = true

	lc.evaluateProbes(true)
	if lc.probeUnsupported {
		t.Fatal("unsupported too early after a single verdict")
	}
	s.lastProbeAt = time.Time{}
	lc.evaluateProbes(true)
	if !lc.probeUnsupported {
		t.Fatal("expected probeUnsupported after two verdicts")
	}

	// 被动采样器现在直接标记 degraded（传统行为）。
	interval := config.HealthCheckInterval
	s.suspected = false
	s.heavy.Store(1)
	lc.evaluateSlotHealth(0, s, interval, true) // 基线重置
	for range config.DegradedPersistCycles {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}
	if !s.degraded.Load() {
		t.Fatal("expected legacy degraded marking after fallback")
	}
}

func TestProbeInconclusiveKeepsState(t *testing.T) {
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeInconclusive
	})
	s := sch.priority.slots[0]
	s.suspected = true

	lc.evaluateProbes(true)

	if !s.suspected {
		t.Fatal("inconclusive probe must keep suspicion")
	}
	if s.probeLowCycles != 0 {
		t.Fatalf("probeLowCycles = %d, want 0", s.probeLowCycles)
	}
	if lc.probeUnsupported {
		t.Fatal("inconclusive must not count as unsupported")
	}
}

func TestProbeCooldown(t *testing.T) {
	calls := 0
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return 10 * 1024, probeSlow
	})
	s := sch.priority.slots[0]
	s.suspected = true
	s.lastProbeAt = time.Now() // 刚才探测过

	lc.evaluateProbes(true)

	if calls != 0 {
		t.Fatal("probe must be skipped within the cooldown")
	}
}

// 得不出结论的探测按连续次数退避：只有 ProbeCooldown 的话同一槽位会无限重试。
func TestProbeInconclusiveBacksOff(t *testing.T) {
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeInconclusive
	})
	s := sch.priority.slots[0]
	s.suspected = true

	lc.evaluateProbes(true)
	if s.probeBackoff != 1 {
		t.Fatalf("probeBackoff = %d after one inconclusive probe, want 1", s.probeBackoff)
	}
	if !s.suspected {
		t.Fatal("an inconclusive probe must keep suspicion")
	}

	// 退避期内即使已过 ProbeCooldown 也不得重试。
	calls := 0
	lc.probeFunc = func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return 0, probeInconclusive
	}
	s.lastProbeAt = time.Now().Add(-config.ProbeCooldown)
	lc.evaluateProbes(true)
	if calls != 0 {
		t.Fatalf("probe calls = %d inside the backoff, want 0", calls)
	}

	// 退避到期后重试，退避继续翻倍。
	s.lastProbeAt = time.Now().Add(-2 * config.ProbeCooldown)
	lc.evaluateProbes(true)
	if calls != 1 || s.probeBackoff != 2 {
		t.Fatalf("calls = %d, probeBackoff = %d, want 1/2", calls, s.probeBackoff)
	}

	// 结论性判决把退避清零。
	lc.probeFunc = func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 10 * 1024 * 1024, probeFast
	}
	s.lastProbeAt = time.Time{}
	s.suspected = true
	lc.evaluateProbes(true)
	if s.probeBackoff != 0 {
		t.Fatalf("probeBackoff = %d after a conclusive verdict, want 0", s.probeBackoff)
	}
}

// 空闲与恢复都不属于"连续 inconclusive"的判定序列：退避必须清零，否则零散的探测会把
// 冷却一路顶到 ProbeMaxBackoff。
func TestProbeProgressResetOnRecoveryAndIdle(t *testing.T) {
	interval := config.HealthCheckInterval
	lc, sch := newTestLifecycle(1, nil)
	s := sch.priority.slots[0]
	s.heavy.Store(1)
	s.suspected = true
	s.probeConn = s.connIdentity()
	s.probeBackoff = 6
	s.probeLowCycles = 1

	// 恢复：吞吐回到阈值以上。
	lc.evaluateSlotHealth(0, s, interval, true) // 基线
	s.bytesRecv.Add(int64(config.DegradedThroughputThreshold) * int64(interval/time.Second))
	lc.evaluateSlotHealth(0, s, interval, true)
	if s.suspected || s.probeBackoff != 0 || s.probeLowCycles != 0 {
		t.Fatalf("after recovery: suspected=%v backoff=%d lowCycles=%d, want false/0/0",
			s.suspected, s.probeBackoff, s.probeLowCycles)
	}

	// 空闲：重流结束。
	s.suspected = true
	s.probeBackoff = 6
	s.probeLowCycles = 1
	s.heavy.Store(0)
	lc.evaluateSlotHealth(0, s, interval, true)
	if s.suspected || s.probeBackoff != 0 || s.probeLowCycles != 0 {
		t.Fatalf("after idle: suspected=%v backoff=%d lowCycles=%d, want false/0/0",
			s.suspected, s.probeBackoff, s.probeLowCycles)
	}
}

func TestProbeCooldownBackoffCap(t *testing.T) {
	if got := probeCooldown(0); got != config.ProbeCooldown {
		t.Fatalf("probeCooldown(0) = %v, want %v", got, config.ProbeCooldown)
	}
	if got := probeCooldown(1); got != 2*config.ProbeCooldown {
		t.Fatalf("probeCooldown(1) = %v, want %v", got, 2*config.ProbeCooldown)
	}
	if got := probeCooldown(64); got != config.ProbeMaxBackoff {
		t.Fatalf("probeCooldown(64) = %v, want the cap %v", got, config.ProbeMaxBackoff)
	}
}

func TestProbeMaxPerInterval(t *testing.T) {
	calls := 0
	lc, sch := newTestLifecycle(3, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return 10 * 1024, probeSlow
	})
	for i := range 3 {
		sch.priority.slots[i].suspected = true
	}

	lc.evaluateProbes(true)

	if calls != config.ProbeMaxPerInterval {
		t.Fatalf("probe calls = %d, want %d", calls, config.ProbeMaxPerInterval)
	}
	if sch.priority.slots[2].probeLowCycles != 0 {
		t.Fatal("the third suspect must wait for the next tick")
	}
}

// 被怀疑的连接已不在这一代时不得探测：判据是连接作用域的，嫌疑随连接一起作废。
func TestProbeSkippedWithoutConnection(t *testing.T) {
	calls := 0
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return 10 * 1024 * 1024, probeFast
	})
	s := sch.priority.slots[0]
	s.generation().conn.Store(nil) // 这一代的连接已经不在了
	s.suspected = true
	s.probeLowCycles = 1

	lc.evaluateProbes(true)

	if calls != 0 {
		t.Fatalf("probe calls = %d without a connection, want 0", calls)
	}
	if s.suspected || s.probeLowCycles != 0 {
		t.Fatal("stale suspicion must be dropped together with its connection")
	}
}

func TestProbesPausedOnCongestedLink(t *testing.T) {
	calls := 0
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return 10 * 1024, probeSlow
	})
	sch.priority.slots[0].suspected = true

	lc.evaluateProbes(false)

	if calls != 0 {
		t.Fatal("no probes while the link is congested")
	}
}

func TestProbesDisabledWithoutProbeFunc(t *testing.T) {
	lc, sch := newTestLifecycle(1, nil)
	sch.priority.slots[0].suspected = true

	lc.evaluateProbes(true)

	if sch.priority.slots[0].probeLowCycles != 0 {
		t.Fatal("no probing without a probe function")
	}
}

func TestRotationDue(t *testing.T) {
	now := time.Now()
	t.Run("lifetime exceeded", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Minute}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(-2 * time.Minute).UnixNano())
		if !lc.rotationDue(s, now) {
			t.Fatal("expected rotation due by age")
		}
	})

	t.Run("bytes exceeded", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Hour, connMaxBytes: 1024}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(time.Hour).UnixNano())
		s.connBytes.Store(2048)
		if !lc.rotationDue(s, now) {
			t.Fatal("expected rotation due by bytes")
		}
	})

	t.Run("fresh connection not due", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Minute, connMaxBytes: 1024}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(time.Minute).UnixNano())
		s.connBytes.Store(512)
		if lc.rotationDue(s, now) {
			t.Fatal("fresh connection must not rotate")
		}
	})

	t.Run("never dialed slot not due by age", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Minute}
		s := &transportSlot{}
		if lc.rotationDue(s, now) {
			t.Fatal("undialed slot must not rotate")
		}
	})
}

func TestRotationLifetimeJitter(t *testing.T) {
	const base = 15 * time.Minute
	span := base * 3 / 10
	min, max := base-span, base+span
	for range 1000 {
		got := rotationLifetime(base)
		if got < min || got > max {
			t.Fatalf("rotationLifetime(%v) = %v, want within [%v, %v]", base, got, min, max)
		}
	}
}

func TestEvaluateRotation(t *testing.T) {
	t.Run("marks expiring and completes rotation when idle", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Minute}
		s := slotWithPool(&http.Transport{})
		s.expireAt.Store(time.Now().Add(-2 * time.Minute).UnixNano())
		s.connBytes.Store(1024)
		s.active.Store(1)
		// 第一轮：仍然忙碌，只标记 expiring。
		lc.evaluateRotation(0, s)
		if !s.expiring.Load() {
			t.Fatal("expected expiring mark")
		}
		// 第二轮：现在空闲，轮换完成并清除标记。
		// 截止时间与字节数也被清零，因此已完成的轮换不会
		// 在复用连接的状态上再次触发。
		s.active.Store(0)
		lc.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("expected expiring cleared after rotation")
		}
		if s.expireAt.Load() != 0 {
			t.Fatalf("expireAt = %d, want 0 after rotation completed", s.expireAt.Load())
		}
		if s.connBytes.Load() != 0 {
			t.Fatalf("connBytes = %d, want 0 after rotation completed", s.connBytes.Load())
		}
		// 第三轮：槽位已无连接，因此每次 tick 都不得再次标记 expiring。
		lc.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("expected no expiring mark after rotation completed")
		}
	})

	t.Run("fresh connection not expiring", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Hour}
		s := slotWithPool(&http.Transport{})
		s.expireAt.Store(time.Now().Add(time.Hour).UnixNano())
		lc.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("fresh connection must not expire")
		}
	})
}

func TestResetRotationClearsMarks(t *testing.T) {
	s := &transportSlot{}
	// 槽位复用时会带着前一条连接的状态；resetRotation 必须恢复到"无连接"基线，
	// 否则 rotationDue 会在复用连接上触发。
	s.degraded.Store(true)
	s.expiring.Store(true)
	s.reverify.Store(true) // 挂起嫌疑同样是连接作用域的
	s.expireAt.Store(time.Now().Add(-time.Minute).UnixNano())
	s.connBytes.Store(1024)

	s.resetRotation()

	if s.degraded.Load() {
		t.Fatal("expected degraded cleared")
	}
	if s.expiring.Load() {
		t.Fatal("expected expiring cleared")
	}
	if s.reverify.Load() {
		t.Fatal("expected the suspend suspicion cleared with the connection")
	}
	if s.connBytes.Load() != 0 {
		t.Fatalf("connBytes = %d, want 0", s.connBytes.Load())
	}
	if s.expireAt.Load() != 0 {
		t.Fatalf("expireAt = %d, want 0 (no connection yet)", s.expireAt.Load())
	}
	// 没有连接的槽位绝不能被判为过期。
	lc := &slotLifecycle{connLifetime: time.Minute}
	if lc.rotationDue(s, time.Now()) {
		t.Fatal("slot without a connection must not be due for rotation")
	}
}

func TestResetConnClearsMarks(t *testing.T) {
	s := &transportSlot{}
	// 一个超过寿命、带字节数的 retiring 槽位（degraded+expiring）：
	// 建立新连接后，轮换状态重新开始，旧连接的 degraded 判定失效。
	s.degraded.Store(true)
	s.expiring.Store(true)
	s.reverify.Store(true) // 新连接天然没有挂起嫌疑
	s.expireAt.Store(time.Now().Add(-time.Minute).UnixNano())
	s.connBytes.Store(1024)

	s.resetConn(time.Hour)

	if s.degraded.Load() {
		t.Fatal("expected degraded cleared on a fresh connection")
	}
	if s.expiring.Load() {
		t.Fatal("expected expiring cleared on a fresh connection")
	}
	if s.reverify.Load() {
		t.Fatal("expected the suspend suspicion cleared on a fresh connection")
	}
	if s.connBytes.Load() != 0 {
		t.Fatalf("connBytes = %d, want 0", s.connBytes.Load())
	}
	if expireAt := s.expireAt.Load(); expireAt <= time.Now().UnixNano() {
		t.Fatalf("expireAt = %d, want a future deadline", expireAt)
	}
}
