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
	// 默认取进程启动时间；客户端会话通过 ResetStartTime/ClearStartTime 覆盖它，
	// 服务端从不重置，因此保持"运行时间 = 进程运行时间"。
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

	tierExpiringScheduled atomic.Int64
	tierHeavyScheduled    atomic.Int64
	tierDegradedScheduled atomic.Int64
	tierRetiringSkipped   atomic.Int64

	slotDegraded         atomic.Int64
	slotRetiredDegraded  atomic.Int64
	connRotated          atomic.Int64
	slotProbes           atomic.Int64
	slotProbeGet         atomic.Int64
	slotProbeHead        atomic.Int64
	slotProbeSlow        atomic.Int64
	slotProbeUnsupported atomic.Int64
	// slotGrownPriority/slotGrownBulk 统计每个池的槽位扩容次数（由懒加载扩容调度器激活的新存活连接）。
	slotGrownPriority atomic.Int64
	slotGrownBulk     atomic.Int64
	// streamsDrained 统计被 relay 排空机制提前关闭的流数：待驱逐槽位上的空闲流在完整空闲超时前被关闭。
	streamsDrained atomic.Int64
	// secondConnInGeneration 统计 net/http 在同一代连接池里再拨一条连接的次数（达到服务端并发流
	// 上限时它会让出 MaxConnsPerHost 计数）。非 0 表示这一代发生过身份顶替，判死必须按流记下的
	// GotConn 身份而不是这一代的当前身份（见 docs/architecture.md）。
	secondConnInGeneration atomic.Int64
	// 挂起复核：识别只把槽位标记为待复核，结论由开流前的一次往返判活给出。
	suspendDetected         atomic.Int64
	suspendReverifyAlive    atomic.Int64
	suspendReverifyReplaced atomic.Int64

	rttMu    sync.Mutex
	rttEWMA  int64 // 纳秒，EWMA 平滑的纯路径 RTT
	rttCount atomic.Int64

	uploadSpeed       atomic.Int64
	downloadSpeed     atomic.Int64
	peakUploadSpeed   atomic.Int64
	peakDownloadSpeed atomic.Int64

	serverTCPStreams      atomic.Int64
	serverUDPStreams      atomic.Int64
	serverICMPStreams     atomic.Int64
	serverHandshakeErrors atomic.Int64
	serverStreamCancels   atomic.Int64
	serverFallbackPages   atomic.Int64
	serverProbes          atomic.Int64

	// startTime 保存单调时钟读数，使 time.Since 不受墙上时钟调整影响；nil 表示没有活跃会话。
	startTime atomic.Pointer[time.Time]
}

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

// 槽位探测按 HTTP 方法分别计数，slotProbes 始终是两者之和。
func RecordSlotProbeGet() {
	g.slotProbes.Add(1)
	g.slotProbeGet.Add(1)
}

func RecordSlotProbeHead() {
	g.slotProbes.Add(1)
	g.slotProbeHead.Add(1)
}

func RecordSlotProbeSlow() { g.slotProbeSlow.Add(1) }
func RecordSlotProbeUnsupported() {
	g.slotProbeUnsupported.Add(1)
}
func RecordSlotGrownPriority() { g.slotGrownPriority.Add(1) }
func RecordSlotGrownBulk()     { g.slotGrownBulk.Add(1) }
func RecordStreamDrained()     { g.streamsDrained.Add(1) }

func RecordSecondConnInGeneration() { g.secondConnInGeneration.Add(1) }

func RecordSuspendDetected()         { g.suspendDetected.Add(1) }
func RecordSuspendReverifyAlive()    { g.suspendReverifyAlive.Add(1) }
func RecordSuspendReverifyReplaced() { g.suspendReverifyReplaced.Add(1) }

const rttAlpha = 0.35

// RecordRTT 提供纯客户端<->服务器路径 RTT 样本：客户端冲刷引导记录与响应到达之间的时间。
// 服务器在拨号源站之前就提交响应，源站延迟因此永远不会进入样本。
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

// RecordServerStreamCancel 统计以"对端已离开该流"结束的服务端会话（客户端正常拆除、
// HTTP/2 流取消、中继空闲超时）。这类结束只记 Debug，计数器使它们仍然可见而不刷日志。
func RecordServerStreamCancel() { g.serverStreamCancels.Add(1) }

func ResetStartTime() {
	now := time.Now()
	g.startTime.Store(&now)
}

func ClearStartTime() {
	g.startTime.Store(nil)
}

// counter 把一个全局计数器绑定到快照里的 int64 字段。ResetCounters 与 Collect 都只遍历这张表，
// 新增计数器时若漏登记，stats 包的测试会失败。
type counter struct {
	ptr *atomic.Int64
	dst func(*Snapshot) *int64
}

// derivedCounter 是没有 int64 快照字段、只派生为字符串的计数器（峰值速度）。
type derivedCounter struct {
	ptr   *atomic.Int64
	apply func(*Snapshot, int64)
}

var counters = []counter{
	{&g.totalStreamsOpened, func(s *Snapshot) *int64 { return &s.TotalStreamsOpened }},
	{&g.totalStreamsClosed, func(s *Snapshot) *int64 { return &s.TotalStreamsClosed }},
	{&g.bytesSent, func(s *Snapshot) *int64 { return &s.BytesSent }},
	{&g.bytesRecv, func(s *Snapshot) *int64 { return &s.BytesRecv }},
	{&g.rawBytesSent, func(s *Snapshot) *int64 { return &s.RawBytesSent }},
	{&g.rawBytesRecv, func(s *Snapshot) *int64 { return &s.RawBytesRecv }},
	{&g.tcpConnections, func(s *Snapshot) *int64 { return &s.TCPConnections }},
	{&g.udpAssociations, func(s *Snapshot) *int64 { return &s.UDPAssociations }},
	{&g.paddingBytes, func(s *Snapshot) *int64 { return &s.PaddingBytes }},
	{&g.recordsWritten, func(s *Snapshot) *int64 { return &s.RecordsWritten }},

	{&g.dnsCacheHits, func(s *Snapshot) *int64 { return &s.DNSCacheHits }},
	{&g.dnsCacheMisses, func(s *Snapshot) *int64 { return &s.DNSCacheMisses }},
	{&g.dnsProxyQueries, func(s *Snapshot) *int64 { return &s.DNSProxyQueries }},
	{&g.dnsDirectQueries, func(s *Snapshot) *int64 { return &s.DNSDirectQueries }},

	{&g.uploadSpeed, func(s *Snapshot) *int64 { return &s.UploadSpeed }},
	{&g.downloadSpeed, func(s *Snapshot) *int64 { return &s.DownloadSpeed }},

	{&g.priorityStreamsOpened, func(s *Snapshot) *int64 { return &s.PriorityStreamsOpened }},
	{&g.bulkStreamsOpened, func(s *Snapshot) *int64 { return &s.BulkStreamsOpened }},
	{&g.priorityFallback, func(s *Snapshot) *int64 { return &s.PriorityFallback }},
	{&g.bulkFallback, func(s *Snapshot) *int64 { return &s.BulkFallback }},

	{&g.rttCount, func(s *Snapshot) *int64 { return &s.RTTCount }},

	{&g.tierExpiringScheduled, func(s *Snapshot) *int64 { return &s.TierExpiringScheduled }},
	{&g.tierHeavyScheduled, func(s *Snapshot) *int64 { return &s.TierHeavyScheduled }},
	{&g.tierDegradedScheduled, func(s *Snapshot) *int64 { return &s.TierDegradedScheduled }},
	{&g.tierRetiringSkipped, func(s *Snapshot) *int64 { return &s.TierRetiringSkipped }},
	{&g.slotDegraded, func(s *Snapshot) *int64 { return &s.SlotDegraded }},
	{&g.slotRetiredDegraded, func(s *Snapshot) *int64 { return &s.SlotRetiredDegraded }},
	{&g.connRotated, func(s *Snapshot) *int64 { return &s.ConnRotated }},
	{&g.secondConnInGeneration, func(s *Snapshot) *int64 { return &s.SecondConnInGeneration }},
	{&g.slotProbes, func(s *Snapshot) *int64 { return &s.SlotProbes }},
	{&g.slotProbeGet, func(s *Snapshot) *int64 { return &s.SlotProbeGet }},
	{&g.slotProbeHead, func(s *Snapshot) *int64 { return &s.SlotProbeHead }},
	{&g.slotProbeSlow, func(s *Snapshot) *int64 { return &s.SlotProbeSlow }},
	{&g.slotProbeUnsupported, func(s *Snapshot) *int64 { return &s.SlotProbeUnsupported }},
	{&g.slotGrownPriority, func(s *Snapshot) *int64 { return &s.SlotGrownPriority }},
	{&g.slotGrownBulk, func(s *Snapshot) *int64 { return &s.SlotGrownBulk }},
	{&g.streamsDrained, func(s *Snapshot) *int64 { return &s.StreamsDrained }},
	{&g.suspendDetected, func(s *Snapshot) *int64 { return &s.SuspendDetected }},
	{&g.suspendReverifyAlive, func(s *Snapshot) *int64 { return &s.SuspendReverifyAlive }},
	{&g.suspendReverifyReplaced, func(s *Snapshot) *int64 { return &s.SuspendReverifyReplaced }},

	{&g.serverTCPStreams, func(s *Snapshot) *int64 { return &s.ServerTCPStreams }},
	{&g.serverUDPStreams, func(s *Snapshot) *int64 { return &s.ServerUDPStreams }},
	{&g.serverICMPStreams, func(s *Snapshot) *int64 { return &s.ServerICMPStreams }},
	{&g.serverHandshakeErrors, func(s *Snapshot) *int64 { return &s.ServerHandshakeErrors }},
	{&g.serverStreamCancels, func(s *Snapshot) *int64 { return &s.ServerStreamCancels }},
	{&g.serverFallbackPages, func(s *Snapshot) *int64 { return &s.ServerFallbackPages }},
	{&g.serverProbes, func(s *Snapshot) *int64 { return &s.ServerProbes }},
}

var derivedCounters = []derivedCounter{
	{&g.peakUploadSpeed, func(s *Snapshot, v int64) { s.PeakUploadSpeedHuman = HumanBytes(v) + "/s" }},
	{&g.peakDownloadSpeed, func(s *Snapshot, v int64) { s.PeakDownloadSpeedHuman = HumanBytes(v) + "/s" }},
}

func ResetCounters() {
	for _, c := range counters {
		c.ptr.Store(0)
	}
	for _, c := range derivedCounters {
		c.ptr.Store(0)
	}
	g.rttMu.Lock()
	g.rttEWMA = 0
	g.rttMu.Unlock()
}

// SessionStats 是会话累计量：流、原始/加密字节与连接次数。
type SessionStats struct {
	TotalStreamsOpened int64 `json:"total_streams_opened"`
	TotalStreamsClosed int64 `json:"total_streams_closed"`
	BytesSent          int64 `json:"bytes_sent"`
	BytesRecv          int64 `json:"bytes_recv"`
	RawBytesSent       int64 `json:"raw_bytes_sent"`
	RawBytesRecv       int64 `json:"raw_bytes_recv"`
	TCPConnections     int64 `json:"tcp_connections"`
	UDPAssociations    int64 `json:"udp_associations"`
	PaddingBytes       int64 `json:"padding_bytes"`
	RecordsWritten     int64 `json:"records_written"`
}

// DNSStats 是客户端 DNS 拦截与缓存的分流计数。
type DNSStats struct {
	DNSCacheHits     int64 `json:"dns_cache_hits"`
	DNSCacheMisses   int64 `json:"dns_cache_misses"`
	DNSProxyQueries  int64 `json:"dns_proxy_queries"`
	DNSDirectQueries int64 `json:"dns_direct_queries"`
}

// SpeedStats 是速度监控器维护的吞吐量；Human 字段是快照时点的派生字符串，峰值只以字符串形式暴露。
type SpeedStats struct {
	UploadSpeed            int64  `json:"upload_speed"`
	DownloadSpeed          int64  `json:"download_speed"`
	UploadSpeedHuman       string `json:"upload_speed_human"`
	DownloadSpeedHuman     string `json:"download_speed_human"`
	PeakUploadSpeedHuman   string `json:"peak_upload_speed_human"`
	PeakDownloadSpeedHuman string `json:"peak_download_speed_human"`
}

// DispatchStats 是分档调度的结果（仅客户端侧）。
type DispatchStats struct {
	PriorityStreamsOpened int64 `json:"priority_streams_opened"`
	BulkStreamsOpened     int64 `json:"bulk_streams_opened"`
	PriorityFallback      int64 `json:"priority_fallback"`
	BulkFallback          int64 `json:"bulk_fallback"`
}

// RTTStats 是纯路径 RTT。除计数器外还有健康循环的判据（AvgRTT），不是纯诊断数据。
type RTTStats struct {
	RTTCount int64   `json:"rtt_count"`
	RTTEWMA  int64   `json:"rtt_ewma_ns"`
	AvgRTTMs float64 `json:"avg_rtt_ms"`
}

// TransportHealthStats 是客户端传输层启发式的内部仪表盘（tier 选择、槽位探测/退役、轮换、
// 挂起复核与同代重拨）。它们只描述本进程的判断过程，字段名不承诺兼容。
type TransportHealthStats struct {
	TierExpiringScheduled int64 `json:"tier_expiring_scheduled"`
	TierHeavyScheduled    int64 `json:"tier_heavy_scheduled"`
	TierDegradedScheduled int64 `json:"tier_degraded_scheduled"`
	TierRetiringSkipped   int64 `json:"tier_retiring_skipped"`

	SlotDegraded           int64 `json:"slot_degraded"`
	SlotRetiredDegraded    int64 `json:"slot_retired_degraded"`
	ConnRotated            int64 `json:"conn_rotated"`
	SecondConnInGeneration int64 `json:"second_conn_in_generation"`
	SlotProbes             int64 `json:"slot_probes"`
	SlotProbeGet           int64 `json:"slot_probe_get"`
	SlotProbeHead          int64 `json:"slot_probe_head"`
	SlotProbeSlow          int64 `json:"slot_probe_slow"`
	SlotProbeUnsupported   int64 `json:"slot_probe_unsupported"`
	SlotGrownPriority      int64 `json:"slot_grown_priority"`
	SlotGrownBulk          int64 `json:"slot_grown_bulk"`
	StreamsDrained         int64 `json:"streams_drained"`

	SuspendDetected         int64 `json:"suspend_detected"`
	SuspendReverifyAlive    int64 `json:"suspend_reverify_alive"`
	SuspendReverifyReplaced int64 `json:"suspend_reverify_replaced"`
}

// ServerStats 只在服务端有值。
type ServerStats struct {
	ServerTCPStreams      int64 `json:"server_tcp_streams,omitempty"`
	ServerUDPStreams      int64 `json:"server_udp_streams,omitempty"`
	ServerICMPStreams     int64 `json:"server_icmp_streams,omitempty"`
	ServerHandshakeErrors int64 `json:"server_handshake_errors,omitempty"`
	ServerStreamCancels   int64 `json:"server_stream_cancels,omitempty"`
	ServerFallbackPages   int64 `json:"server_fallback_pages,omitempty"`
	ServerProbes          int64 `json:"server_probes,omitempty"`
}

// Snapshot 是所有计数器和派生指标的时点副本。计数器按语义分段嵌入，JSON 仍然是平铺的。
type Snapshot struct {
	SessionStats
	DNSStats
	SpeedStats
	DispatchStats
	RTTStats
	TransportHealthStats
	ServerStats

	// 传输层实时状态（连接数与在飞流），由调用方从 Transport 取得后填入。
	transport.TransportStats

	UptimeSeconds float64   `json:"uptime_seconds"`
	StartTime     time.Time `json:"start_time"`
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

func Collect() Snapshot {
	var s Snapshot
	for _, c := range counters {
		*c.dst(&s) = c.ptr.Load()
	}
	for _, c := range derivedCounters {
		c.apply(&s, c.ptr.Load())
	}

	g.rttMu.Lock()
	s.RTTEWMA = g.rttEWMA
	g.rttMu.Unlock()

	s.UploadSpeedHuman = HumanBytes(s.UploadSpeed) + "/s"
	s.DownloadSpeedHuman = HumanBytes(s.DownloadSpeed) + "/s"
	s.AvgRTTMs = float64(time.Duration(s.RTTEWMA).Microseconds()) / 1000.0

	if start := g.startTime.Load(); start != nil {
		s.StartTime = *start
		s.UptimeSeconds = time.Since(*start).Seconds()
	}
	return s
}

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
