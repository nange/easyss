package config

const (
	DefaultTimeout              = 30
	DefaultTCPStreamIdleTimeout = 10 * 60 // seconds
	DefaultConnCountMin         = 8
	DefaultConnCountMax         = 16
	DefaultBatchWindowMS        = 5

	DefaultHTTP2MaxReadFrameSize           = 1 * 1024 * 1024
	DefaultHTTP2ReceiveBufferPerConnection = 64 * 1024 * 1024
	DefaultHTTP2ReceiveBufferPerStream     = 32 * 1024 * 1024

	EndpointTCP  = "/v3/tcp"
	EndpointUDP  = "/v3/udp"
	EndpointICMP = "/v3/icmp"
	EndpointPing = "/v3/ping"
)
