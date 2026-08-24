package config

import "time"

// NextProtos is the ALPN protocol list advertised in TLS handshakes,
// matching what a real Chrome browser offers (h2 preferred, http/1.1 fallback).
var NextProtos = []string{"h2", "http/1.1"}

const (
	// Transport/scheduler defaults: dial timeout, connection-pool size and
	// stream-growth threshold, shaper batch window and cover budget cap.
	// Bounds for conn_count_max / stream_threshold follow right after.
	DefaultTimeout         = 30
	DefaultConnCountMax    = 15
	DefaultStreamThreshold = 4
	DefaultBatchWindowMS   = 3
	DefaultCoverBudgetCap  = 16 * 1024 // 16KB

	// MinConnCountMax/MaxConnCountMax bound conn_count_max: at least 2
	// connections (the scheduler's two-pool split needs a tail slot for the
	// bulk pool), at most 64 so a misconfigured (or maliciously large) value
	// cannot trigger a huge upfront allocation of transport slots.
	MinConnCountMax = 2
	MaxConnCountMax = 64

	// MaxStreamThreshold bounds stream_threshold. The scheduler derives
	// bulkThreshold (2x) and tier-capacity shifts (base << (level-1)) from
	// it in int32, so the cap keeps that arithmetic far from overflow — and
	// aligned with MaxConnCountMax, a threshold beyond the connection cap
	// would never trigger growth anyway.
	MaxStreamThreshold = 64

	// Connection rotation: long-lived TCP+TLS connections are frequently
	// throttled by middleboxes — especially during peak hours — which is
	// why a reconnect feels fast again. A slot whose connection exceeded
	// either limit stops accepting new streams and its idle connection is
	// closed, so the next stream dials a fresh one (invisible to users).
	DefaultConnLifetimeSec = 420               // 7min
	DefaultConnMaxBytes    = 256 * 1024 * 1024 // 256MB，双向（上下行）累计

	// Fallback timeouts used by the server-side constructors when no
	// explicit value is provided. DefaultStreamIdleTimeout mirrors the
	// server's derivation (10 x DefaultTimeout = 300s); the others are
	// defensive defaults for the handler/nextproxy entry points.
	DefaultStreamIdleTimeout = 300 * time.Second // TCP 流空闲超时兜底（= 10 × DefaultTimeout）
	DefaultUDPIdleTimeout    = 30 * time.Second  // UDP 关联空闲超时兜底
	DefaultDialTimeout       = 10 * time.Second  // 出口拨号超时兜底（= DefaultTimeout/3）

	// Defaults shared by config builders, the example config and runtime
	// fallbacks. Keep these as the single source of truth: any code that
	// applies a default must reference the constant, not a literal.
	DefaultServerPort        = 443
	DefaultSocksPort         = 4080
	DefaultHTTPPort          = 5080
	DefaultProtocol          = "h2"
	DefaultMethod            = "aes-256-gcm"
	DefaultPrioritySlotRatio = 0.4
	DefaultCoverBudgetRatio  = 0.03
	DefaultProxyRule         = "auto"
	DefaultIPV6Rule          = "auto"
	DefaultLogLevel          = "info"

	// Heavy-stream detection: a stream is considered "heavy" (monopolizing
	// its shared TCP connection under packet loss) when either condition
	// below is met, after which the hosting slot stops accepting new
	// streams so interactive traffic (e.g. page refreshes) is not dragged
	// down together with the heavy transfer.
	//
	// 1. HeavyStreamThresholdBytes: fast, large transfers are marked as
	//    soon as they cross this cumulative size (either direction).
	// 2. HeavyStreamSlowThresholdBytes + HeavyStreamMinAge: slow transfers
	//    on poor links — even a sub-MB resource takes seconds to load —
	//    are marked once the stream has been alive long enough, so the
	//    isolation kicks in promptly exactly when the link is congested.
	HeavyStreamThresholdBytes     = 1 * 1024 * 1024 // 1MB
	HeavyStreamSlowThresholdBytes = 300 * 1024      // 300KB
	HeavyStreamMinAge             = 5 * time.Second

	// Degraded-slot detection: a slot hosting heavy streams whose download
	// throughput stays below DegradedThroughputThreshold for
	// DegradedPersistCycles consecutive health-check intervals is *suspected*
	// of degradation and gets confirmed by an active probe over the slot's
	// own connection (see EndpointProbe). The mark clears after
	// DegradedRecoverCycles healthy intervals. Detection only runs while
	// the link RTT is at most DegradedMaxRTT: a congested link makes every
	// connection slow, so retiring connections then only adds handshake
	// churn without recovering anything. The RTT is the pure client<->server
	// path RTT (bootstrap round trip, origin latency excluded); a slow
	// origin no longer suppresses detection. When the server does not
	// support probing, the suspicion directly marks the slot (legacy
	// behavior).
	HealthCheckInterval         = 5 * time.Second
	DegradedThroughputThreshold = 80 * 1024 // 80KB/s
	DegradedPersistCycles       = 3
	DegradedRecoverCycles       = 2
	DegradedMaxRTT              = 800 * time.Millisecond

	// Active slot probing: the confirmation step of degraded-slot
	// detection — a slot suspected of degradation (passive throughput
	// below DegradedThroughputThreshold) is confirmed by downloading a
	// pre-generated random payload over the slot's own connection; only a
	// slow probe verdict marks the slot degraded. The probe measures the
	// client<->server path only, so a slow origin or a stalled-but-open
	// stream no longer causes misjudgment.
	ProbePayloadSize    = 128 * 1024       // 128KB，服务端启动时预生成
	ProbeTimeout        = 3 * time.Second  // 单次探测超时（含透明重拨）
	ProbeConfirmCycles  = 2                // 连续慢探测次数 → 标记 degraded
	ProbeCooldown       = 15 * time.Second // 同一 slot 两次探测最小间隔
	ProbeMaxPerInterval = 2                // 每个健康周期最多探测数
	ProbeLinkRefWindow  = 60 * time.Second // 链路参考速度有效窗口

	// Upload flow control on the server side: the per-stream window bounds
	// a single upload stream's in-flight data, capping its throughput at
	// roughly window/RTT. 256KB would pin a single-stream upload to
	// ~6.8Mbps on a 300ms link; 1MB (the stdlib server default) raises that
	// to ~26Mbps, and the 4MB connection window keeps aggregate uploads
	// from being constrained to ~1MB in flight per connection.
	HTTP2ServerMaxReadFrameSize           = 1<<24 - 1 // 16MB-1，nginx/Cloudflare 主流值
	HTTP2ServerReceiveBufferPerConnection = 4 << 20   // 4MB，连接级上行窗口
	HTTP2ServerReceiveBufferPerStream     = 1 << 20   // 1MB，流级上行窗口（stdlib 服务端默认）

	// Client-side HTTP/2 receive windows, mirroring Chrome's values so the
	// transport behaves like a real browser under inspection.
	HTTP2ClientMaxReadFrameSize           = 1 * 1024 * 1024  // 1MB，Chrome MAX_FRAME_SIZE
	HTTP2ClientReceiveBufferPerConnection = 15 * 1024 * 1024 // ~15MB，Chrome 连接级窗口
	HTTP2ClientReceiveBufferPerStream     = 6 * 1024 * 1024  // 6MB，Chrome INITIAL_WINDOW_SIZE
	HTTP2ClientMaxDecoderHeaderTableSize  = 65536            // Chrome HEADER_TABLE_SIZE
	HTTP2ClientMaxResponseHeaderBytes     = 262144           // 256KB，Chrome MAX_HEADER_LIST_SIZE

	// TCP stream buffer sizes: chosen so each batched record stays under
	// the 64KB HTTP/2 frame limit (client packs 4 frames/record, server 2).
	TCPStreamBufferSize       = 15 * 1024 // 客户端，4帧/record (4*(15360+3)=61452 < 64KB)
	ServerTCPStreamBufferSize = 31 * 1024 // 服务端，2帧/record (2*(31744+3)=63494 < 64KB)

	// Endpoint paths: the only paths served by the proxy (forced HTTP/2);
	// every other path returns the fallback HTML page.
	EndpointTCP   = "/v3/tcp"
	EndpointUDP   = "/v3/udp"
	EndpointICMP  = "/v3/icmp"
	EndpointProbe = "/v3/probe"
)
