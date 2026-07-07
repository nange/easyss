package config

const (
	DefaultTimeout       = 30
	DefaultConnCountMin  = 3
	DefaultConnCountMax  = 6
	DefaultBatchWindowMS = 3

	HTTP2ServerMaxReadFrameSize           = 1<<24 - 1  // 16MB-1，nginx/Cloudflare 主流值
	HTTP2ServerReceiveBufferPerConnection = 1 << 20    // 1MB，避免 64KB 瓶颈导致长期运行吞吐量下降
	HTTP2ServerReceiveBufferPerStream     = 256 * 1024 // 256KB，流级别接收窗口

	HTTP2ClientMaxReadFrameSize           = 1 * 1024 * 1024  // 1MB，Chrome MAX_FRAME_SIZE
	HTTP2ClientReceiveBufferPerConnection = 15 * 1024 * 1024 // ~15MB，Chrome 连接级窗口
	HTTP2ClientReceiveBufferPerStream     = 6 * 1024 * 1024  // 6MB，Chrome INITIAL_WINDOW_SIZE
	HTTP2ClientMaxDecoderHeaderTableSize  = 65536            // Chrome HEADER_TABLE_SIZE
	HTTP2ClientMaxResponseHeaderBytes     = 262144           // 256KB，Chrome MAX_HEADER_LIST_SIZE

	TCPStreamBufferSize = 16 * 1024

	EndpointTCP  = "/v3/tcp"
	EndpointUDP  = "/v3/udp"
	EndpointICMP = "/v3/icmp"
)
