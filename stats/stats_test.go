package stats

import (
	"encoding/json"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestResetStartTime(t *testing.T) {
	ClearStartTime()
	before := time.Now()
	ResetStartTime()
	after := time.Now()

	snap := Collect()
	if snap.StartTime.IsZero() {
		t.Fatal("StartTime should not be zero after ResetStartTime")
	}
	if snap.StartTime.Before(before) || snap.StartTime.After(after) {
		t.Fatalf("StartTime %v out of range [%v, %v]", snap.StartTime, before, after)
	}
	if snap.UptimeSeconds < 0 {
		t.Fatalf("UptimeSeconds should be >= 0, got %v", snap.UptimeSeconds)
	}
	// Uptime() 使用单调时钟重新计算 time.Since(StartTime)：它不可能为负，
	// 也不可能小于快照中的运行时间（断言在 Collect 之后执行）。
	// 粗粒度时钟可能得到 0，因此不要求严格为正。
	if u := snap.Uptime(); u < 0 || u.Seconds() < snap.UptimeSeconds {
		t.Fatalf("Uptime() %v inconsistent with UptimeSeconds %v", u, snap.UptimeSeconds)
	}
}

func TestClearStartTime(t *testing.T) {
	ResetStartTime()
	ClearStartTime()

	snap := Collect()
	if !snap.StartTime.IsZero() {
		t.Fatalf("StartTime should be zero after ClearStartTime, got %v", snap.StartTime)
	}
	if snap.UptimeSeconds != 0 {
		t.Fatalf("UptimeSeconds should be 0 after ClearStartTime, got %v", snap.UptimeSeconds)
	}
	if snap.Uptime() != 0 {
		t.Fatalf("Uptime() should be 0 after ClearStartTime, got %v", snap.Uptime())
	}
}

// TestCounterTableCoversEveryAtomicField 守住"一个计数器 = 表里一行"：stats 里新增
// atomic.Int64 却没登记，Reset/Collect 都会静默漏掉它，因此这里让构建失败。
func TestCounterTableCoversEveryAtomicField(t *testing.T) {
	registered := make(map[uintptr]string, len(counters)+2)
	for i, c := range counters {
		addr := reflect.ValueOf(c.ptr).Pointer()
		if prev, dup := registered[addr]; dup {
			t.Fatalf("counters[%d] repeats the counter registered by %s", i, prev)
		}
		registered[addr] = "counters"
	}
	for _, c := range derivedCounters {
		addr := reflect.ValueOf(c.ptr).Pointer()
		if prev, dup := registered[addr]; dup {
			t.Fatalf("derived counter repeats the counter registered by %s", prev)
		}
		registered[addr] = "derivedCounters"
	}

	rv := reflect.ValueOf(g).Elem()
	atomicFields := 0
	for i := range rv.NumField() {
		f := rv.Field(i)
		if f.Type() != reflect.TypeFor[atomic.Int64]() {
			continue
		}
		atomicFields++
		name := rv.Type().Field(i).Name
		addr := f.Addr().Pointer()
		if _, ok := registered[addr]; !ok {
			t.Fatalf("atomic counter %s is missing from counters", name)
		}
		delete(registered, addr)
	}
	if len(registered) != 0 {
		t.Fatalf("%d registered counters do not belong to stats", len(registered))
	}
	if want := len(counters) + len(derivedCounters); atomicFields != want {
		t.Fatalf("stats has %d atomic counters, tables register %d", atomicFields, want)
	}
}

// TestCounterTableTargetsEverySnapshotField 守住映射的另一端：每个 int64 快照字段都要有
// 且只有一个来源，否则 Collect 会留下恒为 0 的字段或让两个计数器互相覆盖。
func TestCounterTableTargetsEverySnapshotField(t *testing.T) {
	var snap Snapshot
	targets := make(map[uintptr]int, len(counters))
	for i, c := range counters {
		addr := reflect.ValueOf(c.dst(&snap)).Pointer()
		if prev, dup := targets[addr]; dup {
			t.Fatalf("counters[%d] and counters[%d] write the same snapshot field", prev, i)
		}
		targets[addr] = i
	}

	var uncovered []string
	walkInt64Fields(reflect.ValueOf(&snap).Elem(), "", func(name string, addr uintptr) {
		if _, ok := targets[addr]; !ok {
			uncovered = append(uncovered, name)
		}
	})
	// RTTEWMA 由 RecordRTT 在 mutex 下维护，不是原子计数器。
	if len(uncovered) != 1 || uncovered[0] != "RTTStats.RTTEWMA" {
		t.Fatalf("snapshot int64 fields without a counter: %v", uncovered)
	}
}

func walkInt64Fields(v reflect.Value, prefix string, fn func(string, uintptr)) {
	if v.Kind() != reflect.Struct {
		return
	}
	for i := range v.NumField() {
		f := v.Field(i)
		name := prefix + v.Type().Field(i).Name
		switch {
		case f.Type() == reflect.TypeFor[time.Time]():
		case f.Kind() == reflect.Struct:
			walkInt64Fields(f, name+".", fn)
		case f.Type() == reflect.TypeFor[int64]():
			fn(name, f.Addr().Pointer())
		}
	}
}

// TestCountersRoundTrip 让每个计数器经过 Collect 与 Reset 各一次：表里的 dst 指错字段
// （与另一个计数器互换）会在这里表现为重复或遗漏，而 Reset 漏项同样会被抓到。
func TestCountersRoundTrip(t *testing.T) {
	t.Cleanup(ResetCounters)
	ResetCounters()

	for i, c := range counters {
		c.ptr.Store(int64(i + 1))
	}
	g.peakUploadSpeed.Store(1 << 20)
	g.peakDownloadSpeed.Store(2 << 20)

	snap := Collect()
	for i, c := range counters {
		if got := *c.dst(&snap); got != int64(i+1) {
			t.Fatalf("counters[%d]: snapshot value = %d, want %d", i, got, i+1)
		}
	}
	if snap.PeakUploadSpeedHuman != "1.0 MB/s" || snap.PeakDownloadSpeedHuman != "2.0 MB/s" {
		t.Fatalf("peak speed human strings = %q, %q", snap.PeakUploadSpeedHuman, snap.PeakDownloadSpeedHuman)
	}

	ResetCounters()
	snap = Collect()
	for i, c := range counters {
		if got := *c.dst(&snap); got != 0 {
			t.Fatalf("counters[%d] not reset: %d", i, got)
		}
	}
	if snap.RTTEWMA != 0 {
		t.Fatalf("RTTEWMA not reset: %d", snap.RTTEWMA)
	}
	if snap.PeakUploadSpeedHuman != "0 B/s" || snap.PeakDownloadSpeedHuman != "0 B/s" {
		t.Fatalf("peak speed not reset: %q, %q", snap.PeakUploadSpeedHuman, snap.PeakDownloadSpeedHuman)
	}
}

// TestSnapshotJSONStaysFlat 守住对外契约：分段只是代码组织方式，JSON 仍然是原来的平铺键。
func TestSnapshotJSONStaysFlat(t *testing.T) {
	ResetCounters()
	b, err := json.Marshal(Collect())
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	for _, key := range []string{
		"total_streams_opened", "bytes_sent", "dns_cache_hits", "upload_speed",
		"priority_fallback", "rtt_count", "avg_rtt_ms", "conn_rotated",
		"suspend_detected", "uptime_seconds",
	} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("snapshot JSON lost the flat key %q", key)
		}
	}
	for _, key := range []string{"SessionStats", "TransportHealthStats", "RTTStats"} {
		if _, ok := decoded[key]; ok {
			t.Errorf("snapshot JSON leaked the section %q", key)
		}
	}
}

// TestCollectConcurrentWithReset 让 Collect 与并发的会话重置一起运行；
// 在 -race 下有意义。
func TestCollectConcurrentWithReset(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			ResetStartTime()
			ResetCounters()
			ClearStartTime()
		}
	}()
	for range 1000 {
		Collect()
	}
	<-done
}

// TestStreamMeterStartsLoopLazily 固定"未越过停顿阈值就不起观察 goroutine"
// 这一内存/调度契约：停顿判定要求 total ≥ stallThreshold，在那之前观测没有
// 任何意义，而每条流都无条件带一个 goroutine 加一个 5s ticker 的代价太大。
func TestStreamMeterStartsLoopLazily(t *testing.T) {
	m := NewStreamMeter("test", "example.com:80")
	defer m.Close()
	if m.loopStarted.Load() {
		t.Fatal("构造时不应启动观察 goroutine")
	}

	// 累计到阈值以下：仍然不应启动。
	m.Add(int(stallThreshold)-1, "read_target")
	if m.loopStarted.Load() {
		t.Fatalf("未越过阈值 (%d) 就不应启动观察 goroutine", stallThreshold)
	}

	// 越过阈值：此时才启动。
	m.Add(1, "read_target")
	if !m.loopStarted.Load() {
		t.Fatal("越过阈值后应启动观察 goroutine")
	}
}

// TestStreamMeterCloseBeforeThreshold 守住从未启动观察 goroutine 时 Close 不能阻塞：
// loopFinished 只在 loop 退出时关闭，Close 必须先用 loopStarted 区分两种情形。
func TestStreamMeterCloseBeforeThreshold(t *testing.T) {
	m := NewStreamMeter("test", "example.com:80")
	m.Add(1024, "read_target")

	done := make(chan struct{})
	go func() {
		m.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("未启动观察 goroutine 时 Close 不应阻塞")
	}
}

// TestStreamMeterCloseIsIdempotent 固定 Close 幂等：TCP handler 与各中继路径
// 都可能在 defer 之外再关一次，而关闭已关闭的 channel 会 panic。
func TestStreamMeterCloseIsIdempotent(t *testing.T) {
	m := NewStreamMeter("test", "example.com:80")
	m.Add(int(stallThreshold), "read_target") // 让观察 goroutine 真的起来
	m.Close()
	m.Close()
}

// TestStreamMeterBytesCountsAllAdds 固定计数语义不因惰性化而改变。
func TestStreamMeterBytesCountsAllAdds(t *testing.T) {
	m := NewStreamMeter("test", "example.com:80")
	defer m.Close()

	m.Add(100, "read_target")
	m.Add(0, "read_target")
	m.Add(-5, "read_target")
	if got := m.Bytes(); got != 100 {
		t.Fatalf("Bytes() = %d, want 100（只累计正数）", got)
	}
}
