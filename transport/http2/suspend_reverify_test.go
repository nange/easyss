package http2

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

// TestSuspendSamplerDetectsSleep 守住判据：挂起只体现为墙钟推进减单调钟推进的离差，
// ticker 的实到间隔量不到它（定时器在自己的时间轴上并没有迟到）。
func TestSuspendSamplerDetectsSleep(t *testing.T) {
	var s suspendSampler
	// 任意的正起点；真实的 suspendOffset 是 1.7e18 量级（墙钟 UnixNano 减去进程内
	// 单调读数），零值留给"还没采样过"。
	const base = int64(100 * time.Second)

	if _, ok := s.sampleOffset(base); ok {
		t.Fatal("the first sample has no predecessor: ok must be false")
	}

	// 正常的一跳：墙钟与单调钟同步前进 ⇒ offset 不变，离差为 0。
	div, ok := s.sampleOffset(base)
	if !ok {
		t.Fatal("the second sample must produce a divergence")
	}
	if div != 0 {
		t.Fatalf("divergence = %v on a normal tick, want 0", div)
	}

	// 挂起 17 分钟：墙钟照走、单调钟冻结 ⇒ offset 恰好跳过睡眠时长。
	div, ok = s.sampleOffset(base + int64(17*time.Minute))
	if !ok {
		t.Fatal("the third sample must produce a divergence")
	}
	if want := 17 * time.Minute; div != want {
		t.Fatalf("divergence = %v, want %v (the invisible sleep)", div, want)
	}
	if div < config.SuspendDivergenceThreshold {
		t.Fatalf("divergence %v below the threshold %v", div, config.SuspendDivergenceThreshold)
	}

	// sample 要把当前时刻换算成这个标量。跑着的时钟上相邻两次采样的离差只有读数
	// 抖动的量级（墙钟与单调读数分别取自运行时，可能相差亚微秒，因此允许轻微为负），
	// 远低于挂起阈值。
	var s2 suspendSampler
	if _, ok := s2.sample(time.Now()); ok {
		t.Fatal("the first sample must only establish the baseline")
	}
	if div, ok := s2.sample(time.Now()); !ok || div > time.Millisecond || div < -time.Millisecond {
		t.Fatalf("sample on a running clock = (%v, %v), want a sub-millisecond divergence", div, ok)
	}
}

// suspendIn 把采样器的基线放到"墙钟比单调钟早 d"的位置，模拟 d 之前睡了一觉：
// 下一次采样就会量到 d 的离差。真实挂起留下的正是这个形状。priming 自己不得产生
// 挂起判定（它把基线往回拨，离差是负的）。
func suspendIn(t *testing.T, s *suspendSampler, d time.Duration) {
	t.Helper()
	if div, ok := s.sampleOffset(suspendOffset(time.Now()) - int64(d)); ok &&
		div >= config.SuspendDivergenceThreshold {
		t.Fatalf("priming the baseline reported a suspension: %v", div)
	}
}

// TestObserveSuspendCountsOncePerSuspension 固定"一次挂起恰好一次武装与记账"：迟到的
// 观测不会重复记账或重新武装槽位，并发采样只有 CAS 的赢家拿到离差。
func TestObserveSuspendCountsOncePerSuspension(t *testing.T) {
	probe := func(context.Context, *transportSlot) (float64, probeVerdict) { return 0, probeInconclusive }

	t.Run("sequential observers", func(t *testing.T) {
		lc, conns := suspectLifecycle(t, 2, probe)
		stats.ResetCounters()

		suspendIn(t, &lc.suspend, 20*time.Minute)
		lc.observeSuspend(time.Now()) // 醒来后第一个开流

		if got := stats.Collect().SuspendDetected; got != 1 {
			t.Fatalf("suspend_detected = %d, want 1", got)
		}
		for i, c := range conns {
			if got := c.closes.Load(); got != 0 {
				t.Fatalf("connection %d closed %d times on a suspicion, want 0", i, got)
			}
		}
		// 复核完成：标记被清掉——这正是旧实现被重复武装的前提。
		for _, s := range lc.sched.priority.slots {
			s.reverify.Store(false)
		}

		// 健康循环的第一个 tick（≤5s 后）观测同一次挂起。
		lc.observeSuspend(time.Now().Add(3 * time.Second))

		if got := stats.Collect().SuspendDetected; got != 1 {
			t.Fatalf("suspend_detected = %d after a late observation, want 1", got)
		}
		for i, s := range lc.sched.priority.slots {
			if s.reverify.Load() {
				t.Fatalf("slot %d re-armed by a late observation of the same suspension", i)
			}
		}
	})

	t.Run("concurrent observers", func(t *testing.T) {
		lc, _ := suspectLifecycle(t, 2, probe)
		stats.ResetCounters()

		suspendIn(t, &lc.suspend, 20*time.Minute)
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() { lc.observeSuspend(time.Now()) })
		}
		wg.Wait()

		if got := stats.Collect().SuspendDetected; got != 1 {
			t.Fatalf("suspend_detected = %d, want exactly 1 per suspension", got)
		}
	})

	t.Run("a second suspension is counted again", func(t *testing.T) {
		lc, _ := suspectLifecycle(t, 2, probe)
		stats.ResetCounters()

		suspendIn(t, &lc.suspend, 20*time.Minute)
		lc.observeSuspend(time.Now())
		lc.observeSuspend(time.Now().Add(3 * time.Second)) // 同一次挂起的迟到观测

		suspendIn(t, &lc.suspend, 20*time.Minute) // 又睡了一觉
		lc.observeSuspend(time.Now())

		if got := stats.Collect().SuspendDetected; got != 2 {
			t.Fatalf("suspend_detected = %d, want 2 (one per suspension)", got)
		}
	})
}

// suspectLifecycle 构建一个带连接的槽位集合：priority 池 n 个、bulk 池 1 个，
// 全部处于活跃状态且各有一条可观测关闭次数的连接。
func suspectLifecycle(t *testing.T, n int, probe func(context.Context, *transportSlot) (float64, probeVerdict)) (*slotLifecycle, []*countingConn) {
	t.Helper()
	lc, sch := newTestLifecycle(n, probe)
	sch.bulk.liveCount.Store(1)

	var conns []*countingConn
	attach := func(s *transportSlot) {
		c := &countingConn{}
		attachConn(s, c)
		// 模拟"有活跃流、刚刚还在采样"的槽位：baseline 非零，且被标记过 heavy。
		s.lastHeavy = 1
		s.bytesRecv.Store(1024)
		conns = append(conns, c)
	}
	for _, s := range sch.priority.slots {
		attach(s)
	}
	attach(sch.bulk.slots[0])
	return lc, conns
}

// TestSuspendMarksSuspectsWithoutClosing 覆盖挂起处理的两条纪律：只标记嫌疑，
// 绝不关闭连接（判死权留给开流前的复核）；健康循环侧另有一次采样基线重置，
// 使挂起期间的"零吞吐"不会被喂给降级检测。
func TestSuspendMarksSuspectsWithoutClosing(t *testing.T) {
	lc, conns := suspectLifecycle(t, 2, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeInconclusive // 不会被调用：识别到挂起只做标记
	})

	suspendIn(t, &lc.suspend, 20*time.Minute)
	lc.observeSuspend(time.Now())

	for i, s := range append([]*transportSlot{lc.sched.priority.slots[0], lc.sched.priority.slots[1]}, lc.sched.bulk.slots[0]) {
		if !s.reverify.Load() {
			t.Fatalf("slot %d: expected a reverify mark", i)
		}
		if s.lastHeavy == 0 {
			t.Fatalf("slot %d: lastHeavy already zero, the reset below would be vacuous", i)
		}
	}
	for i, c := range conns {
		if got := c.closes.Load(); got != 0 {
			t.Fatalf("connection %d closed %d times on a suspicion, want 0", i, got)
		}
	}

	// 健康循环消费挂起事件并重置吞吐采样基线（挂起期间的零吞吐不是降级证据）。
	lc.resetSamplingOnSuspend()
	for i, s := range append([]*transportSlot{lc.sched.priority.slots[0], lc.sched.priority.slots[1]}, lc.sched.bulk.slots[0]) {
		if s.lastHeavy != 0 {
			t.Fatalf("slot %d: lastHeavy = %d, want the sampling baseline reset", i, s.lastHeavy)
		}
	}
}

// TestSuspendWithoutProbeTokenDoesNotMark 固定"无法复核就不标记"：
// 未配置探测令牌时开流路径没有判活手段，把嫌疑留给它等于按嫌疑判死。
// 采样基线仍然要重置（挂起事件的递增与是否有判活手段无关）。
func TestSuspendWithoutProbeTokenDoesNotMark(t *testing.T) {
	lc, conns := suspectLifecycle(t, 1, nil)

	suspendIn(t, &lc.suspend, 20*time.Minute)
	lc.observeSuspend(time.Now())

	for i, s := range lc.sched.priority.slots {
		if s.reverify.Load() {
			t.Fatalf("slot %d: marked without any way to reverify", i)
		}
	}
	for i, c := range conns {
		if got := c.closes.Load(); got != 0 {
			t.Fatalf("connection %d closed %d times, want 0", i, got)
		}
	}

	lc.resetSamplingOnSuspend()
	for i, s := range lc.sched.priority.slots {
		if s.lastHeavy != 0 {
			t.Fatalf("slot %d: lastHeavy = %d, want the sampling baseline reset", i, s.lastHeavy)
		}
	}
}

// TestSlotInvalidateConnIdentity 覆盖复核失效所依赖的身份纪律：身份就是调用方
// 持有的那一代（见 slotTransport），只有它仍是当前一代、且仍持有那条连接时才
// 会被关闭；复核或判死慢了一步，也不会误杀之后新建的连接。
func TestSlotInvalidateConnIdentity(t *testing.T) {
	t.Run("matching identity is closed exactly once", func(t *testing.T) {
		conn := &countingConn{}
		slot, _ := newCountingSlot(conn)
		slot.expiring.Store(true)

		if !slot.invalidateConn(slot.generation(), "test") {
			t.Fatal("expected this call to be the closer")
		}
		if got := conn.closes.Load(); got != 1 {
			t.Fatalf("closes = %d, want 1", got)
		}
		if slot.connIdentity() != nil {
			t.Fatal("the generation's conn pointer must be cleared")
		}
		if slot.expiring.Load() {
			t.Fatal("connection-scoped marks must be cleared with the connection")
		}
		if slot.invalidateConn(slot.generation(), "test") {
			t.Fatal("a second invalidation of the same identity must be a no-op")
		}
		if got := conn.closes.Load(); got != 1 {
			t.Fatalf("closes = %d after a repeated invalidation, want 1", got)
		}
	})

	t.Run("a retired generation never kills the newer connection", func(t *testing.T) {
		oldConn := &countingConn{}
		newConn := &countingConn{}

		slot := slotWithGenFactory()
		oldGen := slot.generation()
		attachConn(slot, oldConn)
		// 另一条流判死：旧连接被关掉，槽位换到新一代，新一代拨出了自己的连接。
		if !slot.invalidateConn(oldGen, "test") {
			t.Fatal("the first invalidation must win")
		}
		newGen := slot.generation()
		newSC := attachConn(slot, newConn)

		// 复核/判死慢了一步：手里拿的还是旧一代（已换代）的身份。
		if slot.invalidateConn(oldGen, "test") {
			t.Fatal("a retired identity must not win its CAS twice")
		}
		if got := oldConn.closes.Load(); got != 1 {
			t.Fatalf("old connection closed %d times, want 1 (the first invalidation only)", got)
		}
		if got := newConn.closes.Load(); got != 0 {
			t.Fatalf("new connection closed %d times, want 0", got)
		}
		if slot.generation() != newGen {
			t.Fatal("a retired generation must not replace the current pool")
		}
		if newGen.conn.Load() != newSC {
			t.Fatal("the current generation must keep its own connection")
		}
	})

	t.Run("nil identity is a no-op", func(t *testing.T) {
		slot := &transportSlot{}
		if slot.invalidateConn(nil, "test") {
			t.Fatal("nil identity must not be reported as closed")
		}
		if slot.invalidateConn(slot.generation(), "test") {
			t.Fatal("a generation without a connection must not be reported as closed")
		}
	})
}

// TestReverifySlotDecisions 用可控的判活结论覆盖复核的三种结局。它是纯决策
// 测试（不经过 net/http）：只断言"谁被关、标记是否清掉"。
func TestReverifySlotDecisions(t *testing.T) {
	tests := []struct {
		name       string
		liveness   func(ctx context.Context, gen *slotTransport) (bool, bool)
		wantClosed int32
		wantCalls  int32
	}{
		{
			name:       "alive keeps the connection",
			liveness:   func(context.Context, *slotTransport) (bool, bool) { return true, true },
			wantClosed: 0,
			wantCalls:  1,
		},
		{
			name:       "unreachable replaces the connection",
			liveness:   func(context.Context, *slotTransport) (bool, bool) { return false, true },
			wantClosed: 1,
			wantCalls:  1,
		},
		{
			name:       "unknown verdict keeps the connection",
			liveness:   func(context.Context, *slotTransport) (bool, bool) { return false, false },
			wantClosed: 0,
			wantCalls:  1,
		},
		{
			name:       "no liveness probe keeps the connection",
			liveness:   nil,
			wantClosed: 0,
			wantCalls:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &countingConn{}
			slot, _ := newCountingSlot(conn)
			slot.reverify.Store(true)

			var calls atomic.Int32
			tr := &http2Transport{}
			if tt.liveness != nil {
				tr.liveness = func(ctx context.Context, gen *slotTransport) (bool, bool) {
					calls.Add(1)
					return tt.liveness(ctx, gen)
				}
			}

			tr.reverifySlot(context.Background(), slot)

			if got := calls.Load(); got != tt.wantCalls {
				t.Fatalf("liveness calls = %d, want %d", got, tt.wantCalls)
			}
			if got := conn.closes.Load(); got != tt.wantClosed {
				t.Fatalf("closes = %d, want %d", got, tt.wantClosed)
			}
			if slot.reverify.Load() {
				t.Fatal("the suspicion must be cleared once the verdict is in")
			}
		})
	}
}

// TestReverifySlotCanceledCallerKeepsSuspicion 固定"调用方取消不是连接的结论"：
// 本地连接刚被关掉就触发复核时，绝不能因此把一条健康连接判死；嫌疑保留给
// 下一次开流。
func TestReverifySlotCanceledCallerKeepsSuspicion(t *testing.T) {
	conn := &countingConn{}
	slot, _ := newCountingSlot(conn)
	slot.reverify.Store(true)

	var calls atomic.Int32
	tr := &http2Transport{
		liveness: func(context.Context, *slotTransport) (bool, bool) {
			calls.Add(1)
			return false, true // 若被调用就会判死
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr.reverifySlot(ctx, slot)

	if got := calls.Load(); got != 0 {
		t.Fatalf("liveness calls = %d on a canceled caller, want 0", got)
	}
	if got := conn.closes.Load(); got != 0 {
		t.Fatalf("closes = %d on a canceled caller, want 0", got)
	}
	if !slot.reverify.Load() {
		t.Fatal("the suspicion must survive for the next open")
	}
}

// TestReverifySlotDetachesProbeFromCallerCancellation 固定判活跑在剥掉调用方
// 取消的上下文上：请求方在复核期间被取消（浏览器关掉本地连接是常态）不能让
// 探测失败，进而把这条连接上其他在飞的流一起切断。
func TestReverifySlotDetachesProbeFromCallerCancellation(t *testing.T) {
	conn := &countingConn{}
	slot, _ := newCountingSlot(conn)
	slot.reverify.Store(true)

	probeStarted := make(chan struct{})
	verdict := make(chan bool, 1)
	tr := &http2Transport{
		liveness: func(ctx context.Context, _ *slotTransport) (bool, bool) {
			close(probeStarted)
			verdict <- ctx.Err() == nil // 探测自己看到的上下文
			return true, true
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-probeStarted
		cancel() // 复核进行中，调用方取消
	}()
	tr.reverifySlot(ctx, slot)
	cancel()

	if !<-verdict {
		t.Fatal("the probe context must not inherit the caller's cancellation")
	}
	if got := conn.closes.Load(); got != 0 {
		t.Fatalf("closes = %d, want 0 (the connection answered)", got)
	}
	if slot.reverify.Load() {
		t.Fatal("a completed verdict must clear the suspicion")
	}
}

// TestMaybeSuspendArmsFromTheOpenPath 守住开流路径自己的挂起检测：待机回来的第一个
// 请求往往早于第一个健康周期，只靠定时器那条流仍会盲踩死连接。
func TestMaybeSuspendArmsFromTheOpenPath(t *testing.T) {
	srv, conns := newH2Server(t)
	tr := newRecoveryTransport(t, srv.URL, "dGVzdHRva2Vu")
	htr := tr.(*http2Transport)
	slot := htr.sched.priority.slots[0]

	open := func() transport.Stream {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     config.EndpointTCP,
			Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
			HighPriority: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return stream
	}

	// 挂起发生时槽位上仍有常驻流：先建立一条真实连接。
	first := open()
	if _, err := first.Write([]byte("abcd")); err != nil {
		t.Fatalf("write on the first stream: %v", err)
	}
	awaitResponse(t, first, 2*time.Second)
	established := slot.connIdentity()
	if established == nil {
		t.Fatal("the first stream must have established a connection")
	}
	stats.ResetCounters()

	// 伪造挂起：把共享基线放到"墙钟比单调钟早 20 分钟"的位置——这正是挂起在采样器
	// 里留下的形状，下一次采样就会量到约 20 分钟的离差。
	suspendIn(t, &htr.lifecycle.suspend, 20*time.Minute)

	htr.lifecycle.observeSuspend(time.Now())
	if !slot.reverify.Load() {
		t.Fatal("the open path must arm the suspect slot by itself")
	}
	if got := stats.Collect().SuspendDetected; got != 1 {
		t.Fatalf("suspend_detected = %d, want 1", got)
	}

	// 采样基线已被推进：紧接着的第二次采样（健康循环的第一个 tick 也是这样）
	// 量到的是"两次采样之间"，不再重复记账。
	htr.lifecycle.observeSuspend(time.Now().Add(3 * time.Second))
	if got := stats.Collect().SuspendDetected; got != 1 {
		t.Fatalf("suspend_detected = %d after a late observation, want 1", got)
	}
	if !slot.reverify.Load() {
		t.Fatal("the late observation must not touch the armed slot")
	}

	// 标记接到了闸门上：下一条流先做一次往返复核，活连接被原样保留。
	second := open()
	defer second.Close() //nolint:errcheck
	if _, err := second.Write([]byte("abcd")); err != nil {
		t.Fatalf("write on the second stream: %v", err)
	}
	awaitResponse(t, second, 2*time.Second)

	if slot.reverify.Load() {
		t.Fatal("the verdict must clear the mark")
	}
	if got := stats.Collect().SuspendReverifyAlive; got != 1 {
		t.Fatalf("suspend_reverify_alive = %d, want 1", got)
	}
	if slot.connIdentity() != established {
		t.Fatal("the live connection must be kept")
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("server saw %d connections, want 1 (no extra dial)", got)
	}
	_ = first.Close()
}

// TestHTTP2Transport_ReverifyKeepsLiveConnection 是端到端的一半：一条健康的
// 连接被标记嫌疑后，开流前的复核必须原样放行（同一个底层连接、不额外拨号），
// 假阳性的代价只是一个 RTT 而不是切断这条连接。
func TestHTTP2Transport_ReverifyKeepsLiveConnection(t *testing.T) {
	srv, conns := newH2Server(t)
	tr := newRecoveryTransport(t, srv.URL, "dGVzdHRva2Vu")
	htr, ok := tr.(*http2Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http2Transport", tr)
	}
	if htr.liveness == nil {
		t.Fatal("a probe token must wire the liveness probe")
	}

	slot := htr.sched.priority.slots[0]

	open := func() transport.Stream {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     config.EndpointTCP,
			Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
			HighPriority: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return stream
	}

	first := open()
	if _, err := first.Write([]byte("abcd")); err != nil {
		t.Fatalf("write on the first stream: %v", err)
	}
	awaitResponse(t, first, 2*time.Second)
	_ = first.Close()

	established := slot.connIdentity()
	if established == nil {
		t.Fatal("the first stream must have established a connection")
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("server saw %d connections, want 1 before the suspicion", got)
	}

	slot.reverify.Store(true)

	second := open()
	defer second.Close() //nolint:errcheck
	if _, err := second.Write([]byte("abcd")); err != nil {
		t.Fatalf("write on the reverified stream: %v", err)
	}
	awaitResponse(t, second, 2*time.Second)

	if slot.reverify.Load() {
		t.Fatal("the reverify mark must be cleared after the verdict")
	}
	if slot.connIdentity() != established {
		t.Fatal("a healthy connection must be kept, not replaced")
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("server saw %d connections, want 1 (no new dial on a false alarm)", got)
	}
}

// TestHTTP2Transport_ReverifyReplacesUnreachableConnection 守住复核判死的落地：连接按
// 身份关闭后，同一槽位的流改走新建连接（静默丢包无法在进程内构造，判活结论由桩给出）。
func TestHTTP2Transport_ReverifyReplacesUnreachableConnection(t *testing.T) {
	srv, conns := newH2Server(t)
	tr := newRecoveryTransport(t, srv.URL, "dGVzdHRva2Vu")
	htr := tr.(*http2Transport)

	var probes atomic.Int32
	htr.liveness = func(context.Context, *slotTransport) (bool, bool) {
		probes.Add(1)
		return false, true // 连接不再能往返
	}

	slot := htr.sched.priority.slots[0]

	open := func() transport.Stream {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     config.EndpointTCP,
			Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
			HighPriority: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return stream
	}

	first := open()
	if _, err := first.Write([]byte("abcd")); err != nil {
		t.Fatalf("write on the first stream: %v", err)
	}
	awaitResponse(t, first, 2*time.Second)

	stale := slot.connIdentity()
	if stale == nil {
		t.Fatal("the first stream must have established a connection")
	}
	slot.reverify.Store(true)

	second := open()
	defer second.Close() //nolint:errcheck

	if got := probes.Load(); got != 1 {
		t.Fatalf("liveness probes = %d, want exactly 1 per suspicion", got)
	}
	if slot.reverify.Load() {
		t.Fatal("the reverify mark must be cleared after the verdict")
	}
	if slot.connIdentity() == stale {
		t.Fatal("the unreachable connection must be dropped")
	}

	// 失效之后由读循环异步回收：新连接在随后的流上建立（生产路径等这一步，
	// 见 client/proxy.settleDeadStream）。这里只要求最终有一条新连接可用。
	deadline := time.Now().Add(3 * time.Second)
	for conns.Load() < 2 && time.Now().Before(deadline) {
		s := open()
		_, _ = s.Write([]byte("abcd"))
		awaitResponse(t, s, 500*time.Millisecond)
		_ = s.Close()
	}
	if got := conns.Load(); got < 2 {
		t.Fatalf("server saw %d connections, want a fresh one after the invalidation", got)
	}
	_ = first.Close()
}
