package config

const (
	DefaultTimeout       = 30
	DefaultConnCountMin  = 3
	DefaultConnCountMax  = 6
	DefaultBatchWindowMS = 3

	HTTP2ServerMaxReadFrameSize           = 1<<24 - 1 // 16MB-1，nginx/Cloudflare 主流值
	HTTP2ServerReceiveBufferPerConnection = 65535     // 不发送连接级 WINDOW_UPDATE（nginx 行为）
	HTTP2ServerReceiveBufferPerStream     = 65535     // SETTINGS_INITIAL_WINDOW_SIZE=64KB（spec 默认）

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
