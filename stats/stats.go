package stats

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/transport"
)

var g = &stats{startTime: time.Now()}

type stats struct {
	totalStreamsOpened atomic.Int64
	totalStreamsClosed atomic.Int64
	bytesSent          atomic.Int64
	bytesRecv          atomic.Int64

	rawBytesSent    atomic.Int64
	rawBytesRecv    atomic.Int64
	tcpConnections  atomic.Int64
	udpAssociations atomic.Int64

	dnsCacheHits     atomic.Int64
	dnsCacheMisses   atomic.Int64
	dnsProxyQueries  atomic.Int64
	dnsDirectQueries atomic.Int64

	paddingBytes   atomic.Int64
	recordsWritten atomic.Int64

	priorityStreamsOpened atomic.Int64
	bulkStreamsOpened     atomic.Int64
	priorityFallback      atomic.Int64
	bulkFallback          atomic.Int64

	rttMu    sync.Mutex
	rttEWMA  int64 // nanoseconds, EWMA-smoothed RTT
	rttCount atomic.Int64

	// Speed tracking (bytes/sec, EWMA-smoothed)
	uploadSpeed   atomic.Int64
	downloadSpeed atomic.Int64

	// Server-side proxy
	serverTCPStreams      atomic.Int64
	serverUDPStreams      atomic.Int64
	serverICMPStreams     atomic.Int64
	serverHandshakeErrors atomic.Int64
	serverFallbackPages   atomic.Int64

	startTime time.Time
}

// --- recorder methods ---

func RecordStreamOpened()   { g.totalStreamsOpened.Add(1) }
func RecordStreamClosed()   { g.totalStreamsClosed.Add(1) }
func RecordBytesSent(n int) { g.bytesSent.Add(int64(n)) }
func RecordBytesRecv(n int) { g.bytesRecv.Add(int64(n)) }

func RecordRawBytesSent(n int) { g.rawBytesSent.Add(int64(n)) }
func RecordRawBytesRecv(n int) { g.rawBytesRecv.Add(int64(n)) }
func RecordTCPConnection()     { g.tcpConnections.Add(1) }
func RecordUDPAssociation()    { g.udpAssociations.Add(1) }

func RecordDNSCacheHit()    { g.dnsCacheHits.Add(1) }
func RecordDNSCacheMiss()   { g.dnsCacheMisses.Add(1) }
func RecordDNSProxyQuery()  { g.dnsProxyQueries.Add(1) }
func RecordDNSDirectQuery() { g.dnsDirectQueries.Add(1) }

func RecordPaddingBytes(n int) { g.paddingBytes.Add(int64(n)) }
func RecordRecordWritten()     { g.recordsWritten.Add(1) }

func RecordStreamOpenedPriority() { g.priorityStreamsOpened.Add(1) }
func RecordStreamOpenedBulk()     { g.bulkStreamsOpened.Add(1) }
func RecordPriorityFallback()     { g.priorityFallback.Add(1) }
func RecordBulkFallback()         { g.bulkFallback.Add(1) }

const rttAlpha = 0.35

func RecordRTT(d time.Duration) {
	g.rttMu.Lock()
	if g.rttCount.Load() == 0 {
		g.rttEWMA = int64(d)
	} else {
		g.rttEWMA = int64(float64(d)*rttAlpha + float64(g.rttEWMA)*(1-rttAlpha))
	}
	g.rttMu.Unlock()
	g.rttCount.Add(1)
}

func RecordServerTCPStream()      { g.serverTCPStreams.Add(1) }
func RecordServerUDPStream()      { g.serverUDPStreams.Add(1) }
func RecordServerICMPStream()     { g.serverICMPStreams.Add(1) }
func RecordServerHandshakeError() { g.serverHandshakeErrors.Add(1) }
func RecordServerFallbackPage()   { g.serverFallbackPages.Add(1) }

// --- snapshot ---

// Snapshot is a point-in-time copy of all counters and derived metrics.
type Snapshot struct {
	// Counters
	TotalStreamsOpened    int64 `json:"total_streams_opened"`
	TotalStreamsClosed    int64 `json:"total_streams_closed"`
	BytesSent             int64 `json:"bytes_sent"`
	BytesRecv             int64 `json:"bytes_recv"`
	RawBytesSent          int64 `json:"raw_bytes_sent"`
	RawBytesRecv          int64 `json:"raw_bytes_recv"`
	TCPConnections        int64 `json:"tcp_connections"`
	UDPAssociations       int64 `json:"udp_associations"`
	DNSCacheHits          int64 `json:"dns_cache_hits"`
	DNSCacheMisses        int64 `json:"dns_cache_misses"`
	DNSProxyQueries       int64 `json:"dns_proxy_queries"`
	DNSDirectQueries      int64 `json:"dns_direct_queries"`
	PaddingBytes          int64 `json:"padding_bytes"`
	RecordsWritten        int64 `json:"records_written"`
	RTTCount              int64 `json:"rtt_count"`
	RTTSum                int64 `json:"rtt_sum_ns"`
	ServerTCPStreams      int64 `json:"server_tcp_streams,omitempty"`
	ServerUDPStreams      int64 `json:"server_udp_streams,omitempty"`
	ServerICMPStreams     int64 `json:"server_icmp_streams,omitempty"`
	ServerHandshakeErrors int64 `json:"server_handshake_errors,omitempty"`
	ServerFallbackPages   int64 `json:"server_fallback_pages,omitempty"`
	PriorityStreamsOpened int64 `json:"priority_streams_opened"`
	BulkStreamsOpened     int64 `json:"bulk_streams_opened"`
	PriorityFallback      int64 `json:"priority_fallback"`
	BulkFallback          int64 `json:"bulk_fallback"`

	// Speed
	UploadSpeed        int64  `json:"upload_speed"`
	DownloadSpeed      int64  `json:"download_speed"`
	UploadSpeedHuman   string `json:"upload_speed_human"`
	DownloadSpeedHuman string `json:"download_speed_human"`

	// Transport stats (embedded, client-side only; zero on server)
	transport.TransportStats

	// Derived
	UptimeSeconds float64 `json:"uptime_seconds"`
	AvgRTTMs      float64 `json:"avg_rtt_ms"`

	StartTime time.Time `json:"start_time"`
}

// ActiveStreamsCount returns the current count of streams opened but not yet closed.
func (s Snapshot) ActiveStreamsCount() int64 {
	return s.TotalStreamsOpened - s.TotalStreamsClosed
}

func (s Snapshot) AvgRTT() time.Duration {
	if s.RTTCount == 0 {
		return 0
	}
	return time.Duration(s.RTTSum)
}

// Uptime returns the duration since StartTime.
func (s Snapshot) Uptime() time.Duration {
	return time.Since(s.StartTime)
}

// Collect returns a point-in-time copy of all counters.
func Collect() Snapshot {
	g.rttMu.Lock()
	ewma := g.rttEWMA
	g.rttMu.Unlock()

	upSpeed := g.uploadSpeed.Load()
	downSpeed := g.downloadSpeed.Load()

	return Snapshot{
		TotalStreamsOpened:    g.totalStreamsOpened.Load(),
		TotalStreamsClosed:    g.totalStreamsClosed.Load(),
		BytesSent:             g.bytesSent.Load(),
		BytesRecv:             g.bytesRecv.Load(),
		RawBytesSent:          g.rawBytesSent.Load(),
		RawBytesRecv:          g.rawBytesRecv.Load(),
		TCPConnections:        g.tcpConnections.Load(),
		UDPAssociations:       g.udpAssociations.Load(),
		DNSCacheHits:          g.dnsCacheHits.Load(),
		DNSCacheMisses:        g.dnsCacheMisses.Load(),
		DNSProxyQueries:       g.dnsProxyQueries.Load(),
		DNSDirectQueries:      g.dnsDirectQueries.Load(),
		PaddingBytes:          g.paddingBytes.Load(),
		RecordsWritten:        g.recordsWritten.Load(),
		RTTSum:                ewma,
		RTTCount:              g.rttCount.Load(),
		ServerTCPStreams:      g.serverTCPStreams.Load(),
		ServerUDPStreams:      g.serverUDPStreams.Load(),
		ServerICMPStreams:     g.serverICMPStreams.Load(),
		ServerHandshakeErrors: g.serverHandshakeErrors.Load(),
		ServerFallbackPages:   g.serverFallbackPages.Load(),
		PriorityStreamsOpened: g.priorityStreamsOpened.Load(),
		BulkStreamsOpened:     g.bulkStreamsOpened.Load(),
		PriorityFallback:      g.priorityFallback.Load(),
		BulkFallback:          g.bulkFallback.Load(),
		UploadSpeed:           upSpeed,
		DownloadSpeed:         downSpeed,
		UploadSpeedHuman:      HumanBytes(upSpeed) + "/s",
		DownloadSpeedHuman:    HumanBytes(downSpeed) + "/s",
		UptimeSeconds:         time.Since(g.startTime).Seconds(),
		AvgRTTMs:              float64(time.Duration(ewma).Microseconds()) / 1000.0,
		StartTime:             g.startTime,
	}
}

// HumanBytes converts bytes to a human-readable string.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div := int64(unit)
	exp := 0
	for n >= div && exp < 4 {
		div *= unit
		exp++
	}
	div /= unit
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp-1])
}
