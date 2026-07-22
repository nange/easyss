package config

type SimpleConfig struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	SN         string `json:"sn"`
	CAPath     string `json:"ca_path"`

	LocalPort        int  `json:"local_port"`
	HTTPPort         int  `json:"http_port"`
	BindAll          bool `json:"bind_all"`
	DisableSysProxy  bool `json:"disable_sys_proxy"`
	EnableForwardDNS bool `json:"enable_forward_dns"`
	EnableTun2socks  bool `json:"enable_tun2socks"`
	EnableQUIC       bool `json:"enable_quic"`

	ProxyRule  string `json:"proxy_rule"`
	IPV6Rule   string `json:"ipv6_rule"`
	DirectFile string `json:"direct_file"`
	ProxyFile  string `json:"proxy_file"`

	Timeout     int    `json:"timeout"`
	LogLevel    string `json:"log_level"`
	LogFilePath string `json:"log_file_path"`

	TunConfig     string `json:"tun_config,omitempty"`
	OutboundProto string `json:"outbound_proto"`
}

func NewSimpleConfig() *SimpleConfig {
	return &SimpleConfig{
		ServerPort: 443,
		LocalPort:  2080,
		Method:     "aes-256-gcm",
		ProxyRule:  "auto",
		IPV6Rule:   "auto",
		Timeout:    30,
		LogLevel:   "info",
	}
}
