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
	// Uptime() recomputes time.Since(StartTime) with the monotonic clock:
	// it can never be negative, nor smaller than the snapshot's uptime
	// (the assertion runs after Collect). Coarse clocks may yield 0, so
	// do not require strictly positive.
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
	RecordRTT(100 * time.Millisecond)
	RecordServerTCPStream()
	RecordServerUDPStream()
	RecordServerICMPStream()
	RecordServerHandshakeError()
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
		snap.RTTCount != 0 || snap.RTTEWMA != 0 ||
		snap.UploadSpeed != 0 || snap.DownloadSpeed != 0 ||
		snap.PeakUploadSpeedHuman != "0 B/s" || snap.PeakDownloadSpeedHuman != "0 B/s" ||
		snap.ServerTCPStreams != 0 || snap.ServerUDPStreams != 0 ||
		snap.ServerICMPStreams != 0 || snap.ServerHandshakeErrors != 0 ||
		snap.ServerFallbackPages != 0 {
		t.Fatalf("counters not fully reset: %+v", snap)
	}
}

// TestCollectConcurrentWithReset exercises Collect against concurrent
// session resets; meaningful under -race.
func TestCollectConcurrentWithReset(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			ResetStartTime()
			ResetCounters()
			ClearStartTime()
		}
	}()
	for i := 0; i < 1000; i++ {
		Collect()
	}
	<-done
}
