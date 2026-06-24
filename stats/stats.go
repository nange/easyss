package stats

import (
	"fmt"
	"sync/atomic"
	"time"
)

var g = &stats{startTime: time.Now()}

type stats struct {
	totalStreamsOpened atomic.Int64
	totalStreamsClosed atomic.Int64
	bytesSent          atomic.Int64
	bytesRecv          atomic.Int64

	proxyBytesSent  atomic.Int64
	proxyBytesRecv  atomic.Int64
	tcpConnections  atomic.Int64
	udpAssociations atomic.Int64

	dnsCacheHits     atomic.Int64
	dnsCacheMisses   atomic.Int64
	dnsProxyQueries  atomic.Int64
	dnsDirectQueries atomic.Int64

	paddingBytes   atomic.Int64
	recordsWritten atomic.Int64

	rttSum   atomic.Int64 // nanoseconds
	rttCount atomic.Int64

	// Server-side proxy
	serverTCPStreams      atomic.Int64
	serverUDPStreams      atomic.Int64
	serverICMPStreams     atomic.Int64
	serverHandshakeErrors atomic.Int64
	serverFallbackPages   atomic.Int64

	startTime time.Time
}

// --- recorder methods ---

func RecordStreamOpened()    { g.totalStreamsOpened.Add(1) }
func RecordStreamClosed()    { g.totalStreamsClosed.Add(1) }
func RecordBytesSent(n int)  { g.bytesSent.Add(int64(n)) }
func RecordBytesRecv(n int)  { g.bytesRecv.Add(int64(n)) }

func RecordProxyBytesSent(n int)  { g.proxyBytesSent.Add(int64(n)) }
func RecordProxyBytesRecv(n int)  { g.proxyBytesRecv.Add(int64(n)) }
func RecordTCPConnection()        { g.tcpConnections.Add(1) }
func RecordUDPAssociation()       { g.udpAssociations.Add(1) }

func RecordDNSCacheHit()    { g.dnsCacheHits.Add(1) }
func RecordDNSCacheMiss()   { g.dnsCacheMisses.Add(1) }
func RecordDNSProxyQuery()  { g.dnsProxyQueries.Add(1) }
func RecordDNSDirectQuery() { g.dnsDirectQueries.Add(1) }

func RecordPaddingBytes(n int) { g.paddingBytes.Add(int64(n)) }
func RecordRecordWritten()     { g.recordsWritten.Add(1) }
func RecordRTT(d time.Duration) {
	g.rttSum.Add(int64(d))
	g.rttCount.Add(1)
}

func RecordServerTCPStream()      { g.serverTCPStreams.Add(1) }
func RecordServerUDPStream()      { g.serverUDPStreams.Add(1) }
func RecordServerICMPStream()     { g.serverICMPStreams.Add(1) }
func RecordServerHandshakeError() { g.serverHandshakeErrors.Add(1) }
func RecordServerFallbackPage()   { g.serverFallbackPages.Add(1) }

// --- snapshot ---

// Snapshot is a point-in-time copy of all counters.
type Snapshot struct {
	TotalStreamsOpened int64     `json:"total_streams_opened"`
	TotalStreamsClosed int64     `json:"total_streams_closed"`
	BytesSent          int64     `json:"bytes_sent"`
	BytesRecv          int64     `json:"bytes_recv"`
	ProxyBytesSent     int64     `json:"proxy_bytes_sent"`
	ProxyBytesRecv     int64     `json:"proxy_bytes_recv"`
	TCPConnections     int64     `json:"tcp_connections"`
	UDPAssociations    int64     `json:"udp_associations"`
	DNSCacheHits       int64     `json:"dns_cache_hits"`
	DNSCacheMisses     int64     `json:"dns_cache_misses"`
	DNSProxyQueries    int64     `json:"dns_proxy_queries"`
	DNSDirectQueries   int64     `json:"dns_direct_queries"`
	PaddingBytes       int64     `json:"padding_bytes"`
	RecordsWritten     int64     `json:"records_written"`
	RTTCount           int64     `json:"rtt_count"`
	RTTSum             int64     `json:"rtt_sum_ns"`
	ServerTCPStreams      int64     `json:"server_tcp_streams"`
	ServerUDPStreams      int64     `json:"server_udp_streams"`
	ServerICMPStreams     int64     `json:"server_icmp_streams"`
	ServerHandshakeErrors int64     `json:"server_handshake_errors"`
	ServerFallbackPages   int64     `json:"server_fallback_pages"`
	StartTime          time.Time `json:"start_time"`
}

// ActiveStreams returns the current count of streams opened but not yet closed.
func (s Snapshot) ActiveStreams() int64 {
	return s.TotalStreamsOpened - s.TotalStreamsClosed
}

func (s Snapshot) AvgRTT() time.Duration {
	if s.RTTCount == 0 {
		return 0
	}
	return time.Duration(s.RTTSum / s.RTTCount)
}

// Uptime returns the duration since StartTime.
func (s Snapshot) Uptime() time.Duration {
	return time.Since(s.StartTime)
}

// Collect returns a point-in-time copy of all counters.
func Collect() Snapshot {
	return Snapshot{
		TotalStreamsOpened: g.totalStreamsOpened.Load(),
		TotalStreamsClosed: g.totalStreamsClosed.Load(),
		BytesSent:          g.bytesSent.Load(),
		BytesRecv:          g.bytesRecv.Load(),
		ProxyBytesSent:     g.proxyBytesSent.Load(),
		ProxyBytesRecv:     g.proxyBytesRecv.Load(),
		TCPConnections:     g.tcpConnections.Load(),
		UDPAssociations:    g.udpAssociations.Load(),
		DNSCacheHits:       g.dnsCacheHits.Load(),
		DNSCacheMisses:     g.dnsCacheMisses.Load(),
		DNSProxyQueries:    g.dnsProxyQueries.Load(),
		DNSDirectQueries:   g.dnsDirectQueries.Load(),
		PaddingBytes:       g.paddingBytes.Load(),
		RecordsWritten:     g.recordsWritten.Load(),
		RTTSum:             g.rttSum.Load(),
		RTTCount:           g.rttCount.Load(),
		ServerTCPStreams:      g.serverTCPStreams.Load(),
		ServerUDPStreams:      g.serverUDPStreams.Load(),
		ServerICMPStreams:     g.serverICMPStreams.Load(),
		ServerHandshakeErrors: g.serverHandshakeErrors.Load(),
		ServerFallbackPages:   g.serverFallbackPages.Load(),
		StartTime:          g.startTime,
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
