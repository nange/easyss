package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type V2Config struct {
	ConfigFile        string          `json:"-"`
	Server            string          `json:"server"`
	ServerPort        int             `json:"server_port"`
	Password          string          `json:"password"`
	Method            string          `json:"method"`
	SN                string          `json:"sn"`
	CAPath            string          `json:"ca_path"`
	LocalPort         int             `json:"local_port"`
	HTTPPort          int             `json:"http_port"`
	BindALL           bool            `json:"bind_all"`
	DisableSysProxy   bool            `json:"disable_sys_proxy"`
	EnableForwardDNS  bool            `json:"enable_forward_dns"`
	EnableTun2socks   bool            `json:"enable_tun2socks"`
	EnableQUIC        bool            `json:"enable_quic"`
	ProxyRule         string          `json:"proxy_rule"`
	IPV6Rule          string          `json:"ipv6_rule"`
	DirectFile string `json:"direct_file"`
	ProxyFile  string `json:"proxy_file"`
	Timeout           int             `json:"timeout"`
	LogLevel          string          `json:"log_level"`
	LogFilePath       string          `json:"log_file_path"`
	TunConfig         json.RawMessage `json:"tun_config"`
	OutboundProto     string          `json:"outbound_proto"`
}

func MigrateV2Config(v2 V2Config) (*ClientConfig, error) {
	proto, err := outboundProtoToProtocol(v2.OutboundProto)
	if err != nil {
		return nil, err
	}

	v3 := ClientConfig{
		ConfigVersion: 3,
			Servers: []*ServerProfile{
				{
					Address:  v2.Server,
				Port:     v2.ServerPort,
				Password: v2.Password,
				Method:   v2.Method,
				SNI:      v2.SN,
				CAPath:   v2.CAPath,
				Default:  true,
			},
		},
		Local: LocalConfig{
			SocksPort:        v2.LocalPort,
			HTTPPort:         v2.HTTPPort,
			BindAll:          v2.BindALL,
			DisableSysProxy:  v2.DisableSysProxy,
			EnableForwardDNS: v2.EnableForwardDNS,
			EnableTun2socks:  v2.EnableTun2socks,
			EnableQUIC:       v2.EnableQUIC,
			TunConfig:        v2.TunConfig,
		},
		Routing: RoutingConfig{
			ProxyRule:  v2.ProxyRule,
			IPV6Rule:   v2.IPV6Rule,
			DirectFile: v2.DirectFile,
			ProxyFile:  v2.ProxyFile,
		},
		Transport: TransportConfig{
			Protocol:       proto,
			EndpointPrefix: "/v3",
			ConnCountMin:   8,
			ConnCountMax:   16,
		},
		Shaper: ShaperConfig{
			BatchWindowMS: 3,
		},
		Log: LogConfig{
			Level:    v2.LogLevel,
			FilePath: v2.LogFilePath,
		},
		Timeout: v2.Timeout,
	}

	if v3.Servers[0].Port == 0 {
		v3.Servers[0].Port = 443
	}
	if v3.Servers[0].Method == "" {
		v3.Servers[0].Method = "aes-256-gcm"
	}
	if v3.Timeout <= 0 {
		v3.Timeout = 30
	}
	if v3.Log.Level == "" {
		v3.Log.Level = "info"
	}
	if v3.Routing.ProxyRule == "" {
		v3.Routing.ProxyRule = "auto"
	}
	if v3.Routing.IPV6Rule == "" {
		v3.Routing.IPV6Rule = "auto"
	}
	if v3.Local.HTTPPort == 0 && v3.Local.SocksPort > 0 {
		v3.Local.HTTPPort = v3.Local.SocksPort + 1000
	}

	return &v3, nil
}

func MigrateV2ToV3(v2Path, v3Path string) error {
	data, err := os.ReadFile(v2Path)
	if err != nil {
		return err
	}

	var v2 V2Config
	if err := json.Unmarshal(data, &v2); err != nil {
		return err
	}

	v3, err := MigrateV2Config(v2)
	if err != nil {
		return err
	}

	v3JSON, err := json.MarshalIndent(v3, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(v3Path, v3JSON, 0644)
}

func outboundProtoToProtocol(proto string) (string, error) {
	switch proto {
	case "", "native":
		return "", nil
	case "h2":
		return "h2", nil
	default:
		return "", fmt.Errorf("invalid outbound_proto %q: valid values are empty, native, h2", proto)
	}
}
