package stats

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/transport"
)

var g = &stats{}

func init() {
	// 默认取进程启动时间；客户端会话通过 ResetStartTime/ClearStartTime
	// 覆盖它，因此服务端（从不重置）保持“运行时间 = 进程运行时间”。
	now := time.Now()
	g.startTime.Store(&now)
}

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

	// 分档调度（客户端侧）：由压力调度器调度到非活跃健康档位的流。
	tierExpiringScheduled atomic.Int64
	tierHeavyScheduled    atomic.Int64
	tierDegradedScheduled atomic.Int64
	// tierRetiringSkipped 统计调度器为流选择槽位时跳过退役中槽位
	// （degraded+expiring）的次数。
	tierRetiringSkipped atomic.Int64

	// 传输健康度（客户端侧）
	slotDegraded         atomic.Int64
	slotRetiredDegraded  atomic.Int64
	connRotated          atomic.Int64
	slotProbes           atomic.Int64
	slotProbeSlow        atomic.Int64
	slotProbeUnsupported atomic.Int64
	// slotGrownPriority/slotGrownBulk 统计每个池的槽位扩容次数
	// （由懒加载扩容调度器激活的新存活连接）。
	slotGrownPriority atomic.Int64
	slotGrownBulk     atomic.Int64
	// streamsDrained 统计被 relay 排空机制提前关闭的流数：
	// 位于待驱逐槽位（expiring/degraded）上的空闲流在完整空闲超时前
	// 被关闭，以便轮换/退役及时完成（参见 relay.BidirectionalWithDrain）。
	streamsDrained atomic.Int64

	rttMu    sync.Mutex
	rttEWMA  int64 // 纳秒，EWMA 平滑的纯路径 RTT
	rttCount atomic.Int64

	// 速度跟踪（字节/秒，EWMA 平滑）
	uploadSpeed       atomic.Int64
	downloadSpeed     atomic.Int64
	peakUploadSpeed   atomic.Int64
	peakDownloadSpeed atomic.Int64

	// 服务端代理
	serverTCPStreams      atomic.Int64
	serverUDPStreams      atomic.Int64
	serverICMPStreams     atomic.Int64
	serverHandshakeErrors atomic.Int64
	serverStreamCancels   atomic.Int64
	serverFallbackPages   atomic.Int64
	serverProbes          atomic.Int64

	// startTime 保存单调时钟读数，使 time.Since 不受墙上时钟调整影响；
	// nil 表示没有活跃会话。
	startTime atomic.Pointer[time.Time]
}

// --- 记录器方法 ---

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
func RecordTierExpiring()         { g.tierExpiringScheduled.Add(1) }
func RecordTierHeavy()            { g.tierHeavyScheduled.Add(1) }
func RecordTierDegraded()         { g.tierDegradedScheduled.Add(1) }
func RecordTierRetiringSkipped()  { g.tierRetiringSkipped.Add(1) }

func RecordSlotDegraded()        { g.slotDegraded.Add(1) }
func RecordSlotRetiredDegraded() { g.slotRetiredDegraded.Add(1) }
func RecordConnRotated()         { g.connRotated.Add(1) }
func RecordSlotProbe()           { g.slotProbes.Add(1) }
func RecordSlotProbeSlow()       { g.slotProbeSlow.Add(1) }
func RecordSlotProbeUnsupported() {
	g.slotProbeUnsupported.Add(1)
}
func RecordSlotGrownPriority() { g.slotGrownPriority.Add(1) }
func RecordSlotGrownBulk()     { g.slotGrownBulk.Add(1) }
func RecordStreamDrained()     { g.streamsDrained.Add(1) }

const rttAlpha = 0.35

// RecordRTT 提供纯客户端<->服务器路径 RTT 样本：即客户端冲刷其引导记录
// （或探测请求到达服务器）与响应到达之间的时间。服务器在拨号源站之前
// 就提交响应，因此源站延迟永远不会进入样本。
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
func RecordServerProbe()          { g.serverProbes.Add(1) }

// RecordServerStreamCancel 统计以"对端已离开该流"结束的服务端会话
// （客户端正常拆除、HTTP/2 流取消、中继空闲超时）。这类结束被降到 Debug
// 级别记录，计数器使它们仍然可见而不刷日志。
func RecordServerStreamCancel() { g.serverStreamCancels.Add(1) }

// --- 会话生命周期 ---

// ResetStartTime 标记新会话的开始，例如客户端启动时。
func ResetStartTime() {
	now := time.Now()
	g.startTime.Store(&now)
}

// ClearStartTime 清除会话开始时间，例如客户端停止时。
func ClearStartTime() {
	g.startTime.Store(nil)
}

// ResetCounters 将所有计数器清零，使每个会话从头开始。
func ResetCounters() {
	g.totalStreamsOpened.Store(0)
	g.totalStreamsClosed.Store(0)
	g.bytesSent.Store(0)
	g.bytesRecv.Store(0)
	g.rawBytesSent.Store(0)
	g.rawBytesRecv.Store(0)
	g.tcpConnections.Store(0)
	g.udpAssociations.Store(0)
	g.dnsCacheHits.Store(0)
	g.dnsCacheMisses.Store(0)
	g.dnsProxyQueries.Store(0)
	g.dnsDirectQueries.Store(0)
	g.paddingBytes.Store(0)
	g.recordsWritten.Store(0)
	g.priorityStreamsOpened.Store(0)
	g.bulkStreamsOpened.Store(0)
	g.priorityFallback.Store(0)
	g.bulkFallback.Store(0)
	g.tierExpiringScheduled.Store(0)
	g.tierHeavyScheduled.Store(0)
	g.tierDegradedScheduled.Store(0)
	g.tierRetiringSkipped.Store(0)
	g.slotDegraded.Store(0)
	g.slotRetiredDegraded.Store(0)
	g.connRotated.Store(0)
	g.slotProbes.Store(0)
	g.slotProbeSlow.Store(0)
	g.slotProbeUnsupported.Store(0)
	g.slotGrownPriority.Store(0)
	g.slotGrownBulk.Store(0)
	g.streamsDrained.Store(0)

	g.rttMu.Lock()
	g.rttEWMA = 0
	g.rttMu.Unlock()
	g.rttCount.Store(0)

	g.uploadSpeed.Store(0)
	g.downloadSpeed.Store(0)
	g.peakUploadSpeed.Store(0)
	g.peakDownloadSpeed.Store(0)

	g.serverTCPStreams.Store(0)
	g.serverUDPStreams.Store(0)
	g.serverICMPStreams.Store(0)
	g.serverHandshakeErrors.Store(0)
	g.serverStreamCancels.Store(0)
	g.serverFallbackPages.Store(0)
	g.serverProbes.Store(0)
}

// --- 快照 ---

// Snapshot 是所有计数器和派生指标的时点副本。
type Snapshot struct {
	// 计数器
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
	RTTEWMA               int64 `json:"rtt_ewma_ns"`
	ServerTCPStreams      int64 `json:"server_tcp_streams,omitempty"`
	ServerUDPStreams      int64 `json:"server_udp_streams,omitempty"`
	ServerICMPStreams     int64 `json:"server_icmp_streams,omitempty"`
	ServerHandshakeErrors int64 `json:"server_handshake_errors,omitempty"`
	ServerStreamCancels   int64 `json:"server_stream_cancels,omitempty"`
	ServerFallbackPages   int64 `json:"server_fallback_pages,omitempty"`
	ServerProbes          int64 `json:"server_probes,omitempty"`
	PriorityStreamsOpened int64 `json:"priority_streams_opened"`
	BulkStreamsOpened     int64 `json:"bulk_streams_opened"`
	PriorityFallback      int64 `json:"priority_fallback"`
	BulkFallback          int64 `json:"bulk_fallback"`

	// 分档调度（仅客户端侧；服务端为零）
	TierExpiringScheduled int64 `json:"tier_expiring_scheduled"`
	TierHeavyScheduled    int64 `json:"tier_heavy_scheduled"`
	TierDegradedScheduled int64 `json:"tier_degraded_scheduled"`
	TierRetiringSkipped   int64 `json:"tier_retiring_skipped"`

	// 传输健康度（仅客户端侧；服务端为零）
	SlotDegraded         int64 `json:"slot_degraded"`
	SlotRetiredDegraded  int64 `json:"slot_retired_degraded"`
	ConnRotated          int64 `json:"conn_rotated"`
	SlotProbes           int64 `json:"slot_probes"`
	SlotProbeSlow        int64 `json:"slot_probe_slow"`
	SlotProbeUnsupported int64 `json:"slot_probe_unsupported"`
	SlotGrownPriority    int64 `json:"slot_grown_priority"`
	SlotGrownBulk        int64 `json:"slot_grown_bulk"`
	StreamsDrained       int64 `json:"streams_drained"`

	// 速度
	UploadSpeed            int64  `json:"upload_speed"`
	DownloadSpeed          int64  `json:"download_speed"`
	UploadSpeedHuman       string `json:"upload_speed_human"`
	DownloadSpeedHuman     string `json:"download_speed_human"`
	PeakUploadSpeedHuman   string `json:"peak_upload_speed_human"`
	PeakDownloadSpeedHuman string `json:"peak_download_speed_human"`

	// 传输统计（内嵌，仅客户端侧；服务端为零）
	transport.TransportStats

	// 派生指标
	UptimeSeconds float64 `json:"uptime_seconds"`
	AvgRTTMs      float64 `json:"avg_rtt_ms"`

	StartTime time.Time `json:"start_time"`
}

func (s Snapshot) AvgRTT() time.Duration {
	if s.RTTCount == 0 {
		return 0
	}
	return time.Duration(s.RTTEWMA)
}

// Uptime 返回自 StartTime 以来的时长，无活跃会话时返回 0。
func (s Snapshot) Uptime() time.Duration {
	if s.StartTime.IsZero() {
		return 0
	}
	return time.Since(s.StartTime)
}

// Collect 返回所有计数器的时点副本。
func Collect() Snapshot {
	g.rttMu.Lock()
	ewma := g.rttEWMA
	g.rttMu.Unlock()

	upSpeed := g.uploadSpeed.Load()
	downSpeed := g.downloadSpeed.Load()

	start := g.startTime.Load()
	var startTime time.Time
	var uptimeSeconds float64
	if start != nil {
		startTime = *start
		uptimeSeconds = time.Since(startTime).Seconds()
	}

	return Snapshot{
		TotalStreamsOpened:     g.totalStreamsOpened.Load(),
		TotalStreamsClosed:     g.totalStreamsClosed.Load(),
		BytesSent:              g.bytesSent.Load(),
		BytesRecv:              g.bytesRecv.Load(),
		RawBytesSent:           g.rawBytesSent.Load(),
		RawBytesRecv:           g.rawBytesRecv.Load(),
		TCPConnections:         g.tcpConnections.Load(),
		UDPAssociations:        g.udpAssociations.Load(),
		DNSCacheHits:           g.dnsCacheHits.Load(),
		DNSCacheMisses:         g.dnsCacheMisses.Load(),
		DNSProxyQueries:        g.dnsProxyQueries.Load(),
		DNSDirectQueries:       g.dnsDirectQueries.Load(),
		PaddingBytes:           g.paddingBytes.Load(),
		RecordsWritten:         g.recordsWritten.Load(),
		RTTEWMA:                ewma,
		RTTCount:               g.rttCount.Load(),
		ServerTCPStreams:       g.serverTCPStreams.Load(),
		ServerUDPStreams:       g.serverUDPStreams.Load(),
		ServerICMPStreams:      g.serverICMPStreams.Load(),
		ServerHandshakeErrors:  g.serverHandshakeErrors.Load(),
		ServerStreamCancels:    g.serverStreamCancels.Load(),
		ServerFallbackPages:    g.serverFallbackPages.Load(),
		ServerProbes:           g.serverProbes.Load(),
		PriorityStreamsOpened:  g.priorityStreamsOpened.Load(),
		BulkStreamsOpened:      g.bulkStreamsOpened.Load(),
		PriorityFallback:       g.priorityFallback.Load(),
		BulkFallback:           g.bulkFallback.Load(),
		TierExpiringScheduled:  g.tierExpiringScheduled.Load(),
		TierHeavyScheduled:     g.tierHeavyScheduled.Load(),
		TierDegradedScheduled:  g.tierDegradedScheduled.Load(),
		TierRetiringSkipped:    g.tierRetiringSkipped.Load(),
		SlotDegraded:           g.slotDegraded.Load(),
		SlotRetiredDegraded:    g.slotRetiredDegraded.Load(),
		ConnRotated:            g.connRotated.Load(),
		SlotProbes:             g.slotProbes.Load(),
		SlotProbeSlow:          g.slotProbeSlow.Load(),
		SlotProbeUnsupported:   g.slotProbeUnsupported.Load(),
		SlotGrownPriority:      g.slotGrownPriority.Load(),
		SlotGrownBulk:          g.slotGrownBulk.Load(),
		StreamsDrained:         g.streamsDrained.Load(),
		UploadSpeed:            upSpeed,
		DownloadSpeed:          downSpeed,
		UploadSpeedHuman:       HumanBytes(upSpeed) + "/s",
		DownloadSpeedHuman:     HumanBytes(downSpeed) + "/s",
		PeakUploadSpeedHuman:   HumanBytes(g.peakUploadSpeed.Load()) + "/s",
		PeakDownloadSpeedHuman: HumanBytes(g.peakDownloadSpeed.Load()) + "/s",
		UptimeSeconds:          uptimeSeconds,
		AvgRTTMs:               float64(time.Duration(ewma).Microseconds()) / 1000.0,
		StartTime:              startTime,
	}
}

// HumanBytes 将字节数转换为人类可读的字符串。
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
