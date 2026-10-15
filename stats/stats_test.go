package stats

import (
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

func TestResetCounters(t *testing.T) {
	RecordStreamOpened()
	RecordStreamOpened()
	RecordStreamClosed()
	RecordBytesSent(100)
	RecordBytesRecv(200)
	RecordRawBytesSent(300)
	RecordRawBytesRecv(400)
	RecordTCPConnection()
	RecordUDPAssociation()
	RecordDNSCacheHit()
	RecordDNSCacheMiss()
	RecordDNSProxyQuery()
	RecordDNSDirectQuery()
	RecordPaddingBytes(500)
	RecordRecordWritten()
	RecordStreamOpenedPriority()
	RecordStreamOpenedBulk()
	RecordPriorityFallback()
	RecordBulkFallback()
	RecordTierExpiring()
	RecordTierHeavy()
	RecordTierDegraded()
	RecordTierRetiringSkipped()
	RecordRTT(100 * time.Millisecond)
	RecordServerTCPStream()
	RecordServerUDPStream()
	RecordServerICMPStream()
	RecordServerHandshakeError()
	RecordServerStreamCancel()
	RecordServerFallbackPage()
	g.uploadSpeed.Store(1000)
	g.downloadSpeed.Store(2000)
	g.peakUploadSpeed.Store(3000)
	g.peakDownloadSpeed.Store(4000)

	ResetCounters()

	snap := Collect()
	if snap.TotalStreamsOpened != 0 || snap.TotalStreamsClosed != 0 ||
		snap.BytesSent != 0 || snap.BytesRecv != 0 ||
		snap.RawBytesSent != 0 || snap.RawBytesRecv != 0 ||
		snap.TCPConnections != 0 || snap.UDPAssociations != 0 ||
		snap.DNSCacheHits != 0 || snap.DNSCacheMisses != 0 ||
		snap.DNSProxyQueries != 0 || snap.DNSDirectQueries != 0 ||
		snap.PaddingBytes != 0 || snap.RecordsWritten != 0 ||
		snap.PriorityStreamsOpened != 0 || snap.BulkStreamsOpened != 0 ||
		snap.PriorityFallback != 0 || snap.BulkFallback != 0 ||
		snap.TierExpiringScheduled != 0 || snap.TierHeavyScheduled != 0 ||
		snap.TierDegradedScheduled != 0 || snap.TierRetiringSkipped != 0 ||
		snap.RTTCount != 0 || snap.RTTEWMA != 0 ||
		snap.UploadSpeed != 0 || snap.DownloadSpeed != 0 ||
		snap.PeakUploadSpeedHuman != "0 B/s" || snap.PeakDownloadSpeedHuman != "0 B/s" ||
		snap.ServerTCPStreams != 0 || snap.ServerUDPStreams != 0 ||
		snap.ServerICMPStreams != 0 || snap.ServerHandshakeErrors != 0 ||
		snap.ServerStreamCancels != 0 ||
		snap.ServerFallbackPages != 0 {
		t.Fatalf("counters not fully reset: %+v", snap)
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
// 任何意义，而此前每条 TCP 流都无条件带一个 goroutine 加一个 5s ticker。
func TestStreamMeterStartsLoopLazily(t *testing.T) {
	m := NewStreamMeter("test", "example.com:80")
	defer m.Close()

	if m.loopStarted.Load() {
		t.Fatal("构造时不应启动观察 goroutine")
	}

	// 累计到阈值以下：仍然不应启动。
	m.Add(int(stallThreshold)-1, "read_target")
	if m.loopStarted.Load() {
		t.Fatalf("未越过阈值 (%d) 就不应启动观察 goroutine", m.Bytes())
	}

	// 越过阈值：此时才启动。
	m.Add(1, "read_target")
	if !m.loopStarted.Load() {
		t.Fatal("越过阈值后应启动观察 goroutine")
	}
}

// TestStreamMeterCloseBeforeThreshold 固定"从未启动观察 goroutine 时 Close
// 不能阻塞"：loopFinished 只有 loop 退出时才关闭，因此 Close 必须先用
// loopStarted 区分两种情形，否则这条路径会永久挂住——而它正是绝大多数流的
// 路径（短命流、空闲长连接）。
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
