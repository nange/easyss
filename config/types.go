package config

import "time"

// NextProtos is the ALPN protocol list advertised in TLS handshakes,
// matching what a real Chrome browser offers (h2 preferred, http/1.1 fallback).
var NextProtos = []string{"h2", "http/1.1"}

const (
	DefaultTimeout         = 30
	DefaultConnCountMax    = 12
	DefaultStreamThreshold = 4
	DefaultBatchWindowMS   = 3
	DefaultCoverBudgetCap  = 16 * 1024 // 16KB

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
	HeavyStreamSlowThresholdBytes = 256 * 1024      // 256KB
	HeavyStreamMinAge             = 3 * time.Second

	HTTP2ServerMaxReadFrameSize           = 1<<24 - 1  // 16MB-1，nginx/Cloudflare 主流值
	HTTP2ServerReceiveBufferPerConnection = 1 << 20    // 1MB，避免 64KB 瓶颈导致长期运行吞吐量下降
	HTTP2ServerReceiveBufferPerStream     = 256 * 1024 // 256KB，流级别接收窗口

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
