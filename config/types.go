package config

const (
	DefaultTimeout       = 30
	DefaultConnCountMin  = 4
	DefaultConnCountMax  = 8
	DefaultBatchWindowMS = 3

	DefaultHTTP2MaxReadFrameSize           = 1 * 1024 * 1024
	DefaultHTTP2ReceiveBufferPerConnection = 16 * 1024 * 1024
	DefaultHTTP2ReceiveBufferPerStream     = 4 * 1024 * 1024

	TCPStreamBufferSize = 16 * 1024

	EndpointTCP  = "/v3/tcp"
	EndpointUDP  = "/v3/udp"
	EndpointICMP = "/v3/icmp"
)
