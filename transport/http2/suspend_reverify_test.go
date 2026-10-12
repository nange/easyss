package http2

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

// TestSuspendSamplerDetectsSleep 保护挂起判据本身：它必须只由"墙钟推进 − 单调钟
// 推进"的离差给出，而不能依赖 ticker 的实到间隔——挂起期间单调钟冻结，定时器
// 在自己的时间轴上并没有迟到。两个读数以标量形式传入，正对应"分别取样、分别
// 保存"这条要求。
func TestSuspendSamplerDetectsSleep(t *testing.T) {
	var s suspendSampler
	const sec = int64(time.Second)

	if _, ok := s.observe(0, 0); ok {
		t.Fatal("the first sample has no predecessor: ok must be false")
	}

	// 正常的一跳：墙钟与单调钟同步推进 5s，离差为 0。
	div, ok := s.observe(5*sec, 5*sec)
	if !ok {
		t.Fatal("the second sample must produce a divergence")
	}
	if div != 0 {
		t.Fatalf("divergence = %v on a normal tick, want 0", div)
	}

	// 挂起 17 分钟：墙钟照走（再 +17m5s），单调钟只走了 5s。
	div, ok = s.observe((17*60+10)*sec, 10*sec)
	if !ok {
		t.Fatal("the third sample must produce a divergence")
	}
	if want := 17 * time.Minute; div != want {
		t.Fatalf("divergence = %v, want %v (the invisible sleep)", div, want)
	}
	if div < sharedconfig.SuspendDivergenceThreshold {
		t.Fatalf("divergence %v below the threshold %v", div, sharedconfig.SuspendDivergenceThreshold)
	}

	// 采样器自己也要能把当前时刻换算成这两个标量。跑着的时钟上，相邻两次采样的
	// 离差只有"读数抖动"的量级（墙钟与单调读数分别取自运行时，可能相差亚微秒，
	// 因此允许轻微为负），远低于挂起阈值。
	s2 := suspendSampler{base: time.Now().Add(-time.Hour)}
	if _, ok := s2.observeNow(time.Now()); ok {
		t.Fatal("the first observeNow must only establish the baseline")
	}
	if div, ok := s2.observeNow(time.Now()); !ok || div > time.Millisecond || div < -time.Millisecond {
		t.Fatalf("observeNow on a running clock = (%v, %v), want a sub-millisecond divergence", div, ok)
	}
}

// TestReportSuspendIsClaimedOnce 固定"一次挂起恰好一条记账"：健康循环与开流路径
// 会各自独立观测到同一次挂起，甚至并发观测，但只有认领者武装与计数。
func TestReportSuspendIsClaimedOnce(t *testing.T) {
	lc, _ := suspectLifecycle(t, 2, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeInconclusive
	})
	stats.ResetCounters()

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { lc.reportSuspend(17 * time.Minute) })
	}
	wg.Wait()

	if got := stats.Collect().SuspendDetected; got != 1 {
		t.Fatalf("suspend_detected = %d, want exactly 1 per suspension", got)
	}
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
		s.conn.Store(&slotConn{c: c})
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

// TestOnSuspendMarksSuspectsWithoutClosing 覆盖挂起处理的两条纪律：只标记
// 嫌疑，绝不关闭连接（判死权留给开流前的复核）；同时重置健康采样基线，
// 使挂起期间的"零吞吐"不会被喂给降级检测。
func TestOnSuspendMarksSuspectsWithoutClosing(t *testing.T) {
	lc, conns := suspectLifecycle(t, 2, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeInconclusive // 不会被调用：onSuspend 只标记
	})

	lc.onSuspend(17 * time.Minute)

	for i, s := range append([]*transportSlot{lc.sched.priority.slots[0], lc.sched.priority.slots[1]}, lc.sched.bulk.slots[0]) {
		if !s.reverify.Load() {
			t.Fatalf("slot %d: expected a reverify mark", i)
		}
		if s.lastHeavy != 0 {
			t.Fatalf("slot %d: lastHeavy = %d, want the sampling baseline reset", i, s.lastHeavy)
		}
	}
	for i, c := range conns {
		if got := c.closes.Load(); got != 0 {
			t.Fatalf("connection %d closed %d times on a suspicion, want 0", i, got)
		}
	}
}

// TestOnSuspendWithoutProbeTokenDoesNotMark 固定"无法复核就不标记"：
// 未配置探测令牌时开流路径没有判活手段，把嫌疑留给它等于按嫌疑判死。
// 采样基线仍然要重置。
func TestOnSuspendWithoutProbeTokenDoesNotMark(t *testing.T) {
	lc, conns := suspectLifecycle(t, 1, nil)

	lc.onSuspend(17 * time.Minute)

	for i, s := range lc.sched.priority.slots {
		if s.reverify.Load() {
			t.Fatalf("slot %d: marked without any way to reverify", i)
		}
		if s.lastHeavy != 0 {
			t.Fatalf("slot %d: lastHeavy = %d, want the sampling baseline reset", i, s.lastHeavy)
		}
	}
	for i, c := range conns {
		if got := c.closes.Load(); got != 0 {
			t.Fatalf("connection %d closed %d times, want 0", i, got)
		}
	}
}

// TestSlotInvalidateConnFromIdentityCAS 覆盖复核失效所依赖的身份纪律：
// 只有"仍是当前连接"的那条会被关闭，复核慢了一步也不会误杀之后新建的连接。
func TestSlotInvalidateConnFromIdentityCAS(t *testing.T) {
	t.Run("matching identity is closed exactly once", func(t *testing.T) {
		conn := &countingConn{}
		slot, sc := newCountingSlot(conn)
		slot.expiring.Store(true)

		if !slot.invalidateConnFrom(sc, "test") {
			t.Fatal("expected this call to be the closer")
		}
		if got := conn.closes.Load(); got != 1 {
			t.Fatalf("closes = %d, want 1", got)
		}
		if slot.conn.Load() != nil {
			t.Fatal("the slot conn pointer must be cleared")
		}
		if slot.expiring.Load() {
			t.Fatal("connection-scoped marks must be cleared with the connection")
		}
		if slot.invalidateConnFrom(sc, "test") {
			t.Fatal("a second invalidation of the same identity must be a no-op")
		}
		if got := conn.closes.Load(); got != 1 {
			t.Fatalf("closes = %d after a repeated invalidation, want 1", got)
		}
	})

	t.Run("stale identity never kills a newer connection", func(t *testing.T) {
		oldConn := &countingConn{}
		slot, oldSC := newCountingSlot(oldConn)
		newConn := &countingConn{}
		newSC := &slotConn{c: newConn}
		slot.conn.Store(newSC) // 复核期间新连接已经顶上

		if slot.invalidateConnFrom(oldSC, "test") {
			t.Fatal("a stale identity must not win the CAS")
		}
		if got := oldConn.closes.Load(); got != 0 {
			t.Fatalf("old connection closed %d times, want 0", got)
		}
		if got := newConn.closes.Load(); got != 0 {
			t.Fatalf("new connection closed %d times, want 0", got)
		}
		if slot.conn.Load() != newSC {
			t.Fatal("the newer connection must stay installed")
		}
	})

	t.Run("nil identity is a no-op", func(t *testing.T) {
		slot := &transportSlot{}
		if slot.invalidateConnFrom(nil, "test") {
			t.Fatal("nil identity must not be reported as closed")
		}
	})
}

// TestReverifySlotDecisions 用可控的判活结论覆盖复核的三种结局。它是纯决策
// 测试（不经过 net/http）：只断言"谁被关、标记是否清掉"。
func TestReverifySlotDecisions(t *testing.T) {
	tests := []struct {
		name       string
		liveness   func(ctx context.Context, slot *transportSlot) (bool, bool)
		wantClosed int32
		wantCalls  int32
	}{
		{
			name:       "alive keeps the connection",
			liveness:   func(context.Context, *transportSlot) (bool, bool) { return true, true },
			wantClosed: 0,
			wantCalls:  1,
		},
		{
			name:       "unreachable replaces the connection",
			liveness:   func(context.Context, *transportSlot) (bool, bool) { return false, true },
			wantClosed: 1,
			wantCalls:  1,
		},
		{
			name:       "unknown verdict keeps the connection",
			liveness:   func(context.Context, *transportSlot) (bool, bool) { return false, false },
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
				tr.liveness = func(ctx context.Context, s *transportSlot) (bool, bool) {
					calls.Add(1)
					return tt.liveness(ctx, s)
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
		liveness: func(context.Context, *transportSlot) (bool, bool) {
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
		liveness: func(ctx context.Context, _ *transportSlot) (bool, bool) {
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

// TestMaybeSuspendArmsFromTheOpenPath 覆盖 S4：待机回来的第一个请求往往早于第一个
// 健康周期，因此开流路径必须自己发现挂起并武装嫌疑，而不是等定时器。测试用"墙钟
// 基线停在过去、单调钟基线是当前值"伪造一次挂起（这正是挂起在采样器里留下的样子），
// 然后验证：武装、记账恰好一次、第二个请求的复核把活连接原样放行。
func TestMaybeSuspendArmsFromTheOpenPath(t *testing.T) {
	srv, conns := newH2Server(t)
	tr := newRecoveryTransport(t, srv.URL, "dGVzdHRva2Vu")
	htr := tr.(*http2Transport)
	slot := htr.sched.priority.slots[0]

	open := func() transport.Stream {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     sharedconfig.EndpointTCP,
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
	established := slot.conn.Load()
	if established == nil {
		t.Fatal("the first stream must have established a connection")
	}
	stats.ResetCounters()

	// 伪造挂起：墙钟照走 20 分钟，单调钟冻结在当前值。
	now := time.Now()
	htr.suspend.observe(
		now.Add(-20*time.Minute).Round(0).UnixNano(),
		now.Sub(htr.suspend.base).Nanoseconds(),
	)

	htr.maybeSuspend()
	if !slot.reverify.Load() {
		t.Fatal("the open path must arm the suspect slot by itself")
	}
	if got := stats.Collect().SuspendDetected; got != 1 {
		t.Fatalf("suspend_detected = %d, want 1", got)
	}

	// 采样基线已被推进：紧接着的第二次采样不再重复记账。
	htr.maybeSuspend()
	if got := stats.Collect().SuspendDetected; got != 1 {
		t.Fatalf("suspend_detected = %d after a fresh sample, want 1", got)
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
	if slot.conn.Load() != established {
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
			Endpoint:     sharedconfig.EndpointTCP,
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

	established := slot.conn.Load()
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
	if slot.conn.Load() != established {
		t.Fatal("a healthy connection must be kept, not replaced")
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("server saw %d connections, want 1 (no new dial on a false alarm)", got)
	}
}

// TestHTTP2Transport_ReverifyReplacesUnreachableConnection 是端到端的另一半：
// 复核判死时，那条连接被按身份关闭，随后同一槽位的流在新建的连接上继续。
// 判活结论由桩给出（真实的"静默丢包"无法在进程内构造），这里验证的是决策被
// 真的接到了 Open 路径上。
func TestHTTP2Transport_ReverifyReplacesUnreachableConnection(t *testing.T) {
	srv, conns := newH2Server(t)
	tr := newRecoveryTransport(t, srv.URL, "dGVzdHRva2Vu")
	htr := tr.(*http2Transport)

	var probes atomic.Int32
	htr.liveness = func(context.Context, *transportSlot) (bool, bool) {
		probes.Add(1)
		return false, true // 连接不再能往返
	}

	slot := htr.sched.priority.slots[0]

	open := func() transport.Stream {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     sharedconfig.EndpointTCP,
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

	stale := slot.conn.Load()
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
	if slot.conn.Load() == stale {
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
