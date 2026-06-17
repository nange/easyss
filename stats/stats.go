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

	// Server-side proxy
	serverTCPStreams      atomic.Int64
	serverUDPStreams      atomic.Int64
	serverICMPStreams     atomic.Int64
	serverPingStreams     atomic.Int64
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

func RecordServerTCPStream()      { g.serverTCPStreams.Add(1) }
func RecordServerUDPStream()      { g.serverUDPStreams.Add(1) }
func RecordServerICMPStream()     { g.serverICMPStreams.Add(1) }
func RecordServerPingStream()     { g.serverPingStreams.Add(1) }
func RecordServerHandshakeError() { g.serverHandshakeErrors.Add(1) }
func RecordServerFallbackPage()   { g.serverFallbackPages.Add(1) }

// --- snapshot ---

// Snapshot is a point-in-time copy of all counters.
type Snapshot struct {
	TotalStreamsOpened int64
	TotalStreamsClosed int64
	BytesSent          int64
	BytesRecv          int64
	ProxyBytesSent     int64
	ProxyBytesRecv     int64
	TCPConnections     int64
	UDPAssociations    int64
	DNSCacheHits       int64
	DNSCacheMisses     int64
	DNSProxyQueries    int64
	DNSDirectQueries   int64
	PaddingBytes       int64
	RecordsWritten     int64
	ServerTCPStreams      int64
	ServerUDPStreams      int64
	ServerICMPStreams     int64
	ServerPingStreams     int64
	ServerHandshakeErrors int64
	ServerFallbackPages   int64
	StartTime          time.Time
}

// ActiveStreams returns the current count of streams opened but not yet closed.
func (s Snapshot) ActiveStreams() int64 {
	return s.TotalStreamsOpened - s.TotalStreamsClosed
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
		ServerTCPStreams:      g.serverTCPStreams.Load(),
		ServerUDPStreams:      g.serverUDPStreams.Load(),
		ServerICMPStreams:     g.serverICMPStreams.Load(),
		ServerPingStreams:     g.serverPingStreams.Load(),
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
