package http2

import (
	"context"
	"net/http"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
)

func TestEvaluateSlotHealth(t *testing.T) {
	interval := sharedconfig.HealthCheckInterval
	// 传统模式（probeUnsupported）：被动采样器直接标记 degraded，
	// 与探测功能出现之前的行为一致。
	lc := &slotLifecycle{probeUnsupported: true}

	newHeavySlot := func() *transportSlot {
		s := &transportSlot{t: &http.Transport{}}
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
		for i := range sharedconfig.DegradedPersistCycles - 1 {
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
		for range sharedconfig.DegradedPersistCycles {
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
		s := &transportSlot{t: &http.Transport{}}
		for range sharedconfig.DegradedPersistCycles + 2 {
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
		for range sharedconfig.DegradedPersistCycles + 2 {
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

// newTestLifecycle 在 n 个存活槽位上构建生命周期，并给定探测函数
// （nil 表示禁用探测）。全部 n 个槽位都位于 priority 池（bulk 池保持为空），
// 因此测试以 priority.slots[i] 访问它们。
func newTestLifecycle(n int, probe func(context.Context, *transportSlot) (float64, probeVerdict)) (*slotLifecycle, *slotScheduler) {
	slots := make([]*transportSlot, n)
	for i := range slots {
		slots[i] = &transportSlot{t: &http.Transport{}}
	}
	sch := &slotScheduler{
		priority: &slotPool{
			slots:    slots,
			maxSlots: n,
			base:     8,
		},
		bulk: &slotPool{
			slots:    []*transportSlot{{t: &http.Transport{}}},
			maxSlots: 1,
			base:     16,
		},
	}
	sch.priority.liveCount.Store(int32(n))
	lc := &slotLifecycle{sched: sch, probeFunc: probe}
	return lc, sch
}

func TestSuspicionInsteadOfDirectMark(t *testing.T) {
	interval := sharedconfig.HealthCheckInterval
	// 探测模式：配置了探测函数，因此被动低速只产生嫌疑；
	// degraded 标记由探测确认。（这里的假探测函数不会被调用——
	// 只有被动采样器在运行。）
	lc := &slotLifecycle{probeFunc: func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeInconclusive
	}}
	s := &transportSlot{t: &http.Transport{}}
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
	for range sharedconfig.DegradedPersistCycles {
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
	interval := sharedconfig.HealthCheckInterval
	// 未配置探测函数（例如没有探测令牌）：被动采样器保持传统的直接标记。
	lc := &slotLifecycle{}
	s := &transportSlot{t: &http.Transport{}}
	s.heavy.Store(1)

	lc.evaluateSlotHealth(0, s, interval, true) // 基线重置
	for range sharedconfig.DegradedPersistCycles {
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
	if lc.linkRefSpeed != fastSpeed {
		t.Fatalf("linkRefSpeed = %v, want %v", lc.linkRefSpeed, fastSpeed)
	}
}

func TestProbeSlowRespectsLinkReference(t *testing.T) {
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 30 * 1024, probeSlow
	})
	s := sch.priority.slots[0]

	// 新的链路参考速度低于 degraded 阈值，说明整条链路才是瓶颈：
	// 慢探测不得归咎于该槽位。
	lc.linkRefSpeed = 32 * 1024
	lc.linkRefAt = time.Now()
	s.suspected = true
	lc.evaluateProbes(true)
	if s.degraded.Load() || s.probeLowCycles != 0 || s.suspected {
		t.Fatal("must not mark or keep suspicion while the link itself is slow")
	}

	// 链路参考健康：该槽位的连接才是问题所在。
	lc.linkRefSpeed = 1024 * 1024
	lc.linkRefAt = time.Now()
	s.suspected = true
	s.lastProbeAt = time.Time{}
	lc.evaluateProbes(true)
	s.lastProbeAt = time.Time{}
	lc.evaluateProbes(true)
	if !s.degraded.Load() {
		t.Fatal("expected degraded with a healthy link reference")
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
	interval := sharedconfig.HealthCheckInterval
	s.suspected = false
	s.heavy.Store(1)
	lc.evaluateSlotHealth(0, s, interval, true) // 基线重置
	for range sharedconfig.DegradedPersistCycles {
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

	if calls != sharedconfig.ProbeMaxPerInterval {
		t.Fatalf("probe calls = %d, want %d", calls, sharedconfig.ProbeMaxPerInterval)
	}
	if sch.priority.slots[2].probeLowCycles != 0 {
		t.Fatal("the third suspect must wait for the next tick")
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
		s := &transportSlot{t: &http.Transport{}}
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
		s := &transportSlot{t: &http.Transport{}}
		s.expireAt.Store(time.Now().Add(time.Hour).UnixNano())
		lc.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("fresh connection must not expire")
		}
	})
}

func TestResetRotationClearsMarks(t *testing.T) {
	s := &transportSlot{}
	// 被 grow 重新激活（或完成轮换后）的槽位带着前一条连接的状态：
	// 过期的截止时间、承载的字节数以及 expiring/degraded 判定。
	// resetRotation 必须把它恢复到"无连接"基线：无标记、零截止时间、
	// 零字节——这样 rotationDue 绝不会在复用连接的状态上触发。
	s.degraded.Store(true)
	s.expiring.Store(true)
	s.expireAt.Store(time.Now().Add(-time.Minute).UnixNano())
	s.connBytes.Store(1024)

	s.resetRotation()

	if s.degraded.Load() {
		t.Fatal("expected degraded cleared")
	}
	if s.expiring.Load() {
		t.Fatal("expected expiring cleared")
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
	s.expireAt.Store(time.Now().Add(-time.Minute).UnixNano())
	s.connBytes.Store(1024)

	s.resetConn(time.Hour)

	if s.degraded.Load() {
		t.Fatal("expected degraded cleared on a fresh connection")
	}
	if s.expiring.Load() {
		t.Fatal("expected expiring cleared on a fresh connection")
	}
	if s.connBytes.Load() != 0 {
		t.Fatalf("connBytes = %d, want 0", s.connBytes.Load())
	}
	if expireAt := s.expireAt.Load(); expireAt <= time.Now().UnixNano() {
		t.Fatalf("expireAt = %d, want a future deadline", expireAt)
	}
}
