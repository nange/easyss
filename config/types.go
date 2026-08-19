package config

import "time"

// NextProtos is the ALPN protocol list advertised in TLS handshakes,
// matching what a real Chrome browser offers (h2 preferred, http/1.1 fallback).
var NextProtos = []string{"h2", "http/1.1"}

const (
	DefaultTimeout         = 30
	DefaultConnCountMax    = 18
	DefaultStreamThreshold = 4
	DefaultBatchWindowMS   = 3
	DefaultCoverBudgetCap  = 16 * 1024 // 16KB

	// Defaults shared by config builders, the example config and runtime
	// fallbacks. Keep these as the single source of truth: any code that
	// applies a default must reference the constant, not a literal.
	DefaultServerPort        = 443
	DefaultSocksPort         = 4080
	DefaultHTTPPort          = 5080
	DefaultProtocol          = "h2"
	DefaultMethod            = "aes-256-gcm"
	DefaultPrioritySlotRatio = 0.5
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
	// DegradedPersistCycles consecutive health-check intervals is marked
	// degraded — new streams avoid it and its idle connection is retired
	// early instead of lingering. The mark clears after
	// DegradedRecoverCycles healthy intervals. Detection only runs while
	// the link RTT is at most DegradedMaxRTT: a congested link makes every
	// connection slow, so retiring connections then only adds handshake
	// churn without recovering anything.
	HealthCheckInterval         = 5 * time.Second
	DegradedThroughputThreshold = 64 * 1024 // 64KB/s
	DegradedPersistCycles       = 3
	DegradedRecoverCycles       = 2
	DegradedMaxRTT              = 500 * time.Millisecond

	// Connection rotation: long-lived TCP+TLS connections are frequently
	// throttled by middleboxes — especially during peak hours — which is
	// why a reconnect feels fast again. A slot whose connection exceeded
	// either limit stops accepting new streams and its idle connection is
	// closed, so the next stream dials a fresh one (invisible to users).
	DefaultConnLifetimeSec = 900               // 15min
	DefaultConnMaxBytes    = 150 * 1024 * 1024 // 150MB，双向（上下行）累计

	// Upload flow control on the server side: the per-stream window bounds
	// a single upload stream's in-flight data, capping its throughput at
	// roughly window/RTT. 256KB would pin a single-stream upload to
	// ~6.8Mbps on a 300ms link; 1MB (the stdlib server default) raises that
	// to ~26Mbps, and the 4MB connection window keeps aggregate uploads
	// from being constrained to ~1MB in flight per connection.
	HTTP2ServerMaxReadFrameSize           = 1<<24 - 1 // 16MB-1，nginx/Cloudflare 主流值
	HTTP2ServerReceiveBufferPerConnection = 4 << 20   // 4MB，连接级上行窗口
	HTTP2ServerReceiveBufferPerStream     = 1 << 20   // 1MB，流级上行窗口（stdlib 服务端默认）

	HTTP2ClientMaxReadFrameSize           = 1 * 1024 * 1024  // 1MB，Chrome MAX_FRAME_SIZE
	HTTP2ClientReceiveBufferPerConnection = 15 * 1024 * 1024 // ~15MB，Chrome 连接级窗口
	HTTP2ClientReceiveBufferPerStream     = 6 * 1024 * 1024  // 6MB，Chrome INITIAL_WINDOW_SIZE
	HTTP2ClientMaxDecoderHeaderTableSize  = 65536            // Chrome HEADER_TABLE_SIZE
	HTTP2ClientMaxResponseHeaderBytes     = 262144           // 256KB，Chrome MAX_HEADER_LIST_SIZE

	TCPStreamBufferSize       = 15 * 1024 // 客户端，4帧/record (4*(15360+3)=61452 < 64KB)
	ServerTCPStreamBufferSize = 31 * 1024 // 服务端，2帧/record (2*(31744+3)=63494 < 64KB)

	EndpointTCP  = "/v3/tcp"
	EndpointUDP  = "/v3/udp"
	EndpointICMP = "/v3/icmp"
)
