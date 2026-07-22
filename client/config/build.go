package config

import (
	"encoding/json"
	"fmt"

	sharedconfig "github.com/nange/easyss/v3/config"
)

func BuildSimpleConfig(s *sharedconfig.SimpleConfig) (*ClientConfig, error) {
	if s.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if s.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	proto, err := outboundProtoToProtocol(s.OutboundProto)
	if err != nil {
		return nil, err
	}

	cfg := &ClientConfig{
		ConfigVersion: 3,
		Servers: []*ServerProfile{{
			Address:  s.Server,
			Port:     s.ServerPort,
			Password: s.Password,
			Method:   s.Method,
			SNI:      s.SN,
			CAPath:   s.CAPath,
			Default:  true,
		}},
		Local: LocalConfig{
			SocksPort:        s.LocalPort,
			HTTPPort:         s.HTTPPort,
			BindAll:          s.BindAll,
			DisableSysProxy:  s.DisableSysProxy,
			EnableForwardDNS: s.EnableForwardDNS,
			EnableTun2socks:  s.EnableTun2socks,
			EnableQUIC:       s.EnableQUIC,
			TunConfig:        jsonTunConfig(s.TunConfig),
		},
		Routing: RoutingConfig{
			ProxyRule:  s.ProxyRule,
			IPV6Rule:   s.IPV6Rule,
			DirectFile: s.DirectFile,
			ProxyFile:  s.ProxyFile,
		},
		Transport: TransportConfig{
			Protocol:     proto,
			ConnCountMax: sharedconfig.DefaultConnCountMax,
		},
		Shaper: ShaperConfig{
			BatchWindowMS: 3,
		},
		Log: LogConfig{
			Level:    s.LogLevel,
			FilePath: s.LogFilePath,
		},
		Timeout: s.Timeout,
	}

	if cfg.Servers[0].Port == 0 {
		cfg.Servers[0].Port = 443
	}
	if cfg.Servers[0].Method == "" {
		cfg.Servers[0].Method = "aes-256-gcm"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Routing.ProxyRule == "" {
		cfg.Routing.ProxyRule = "auto"
	}
	if cfg.Routing.IPV6Rule == "" {
		cfg.Routing.IPV6Rule = "auto"
	}
	if cfg.Local.HTTPPort == 0 && cfg.Local.SocksPort > 0 {
		cfg.Local.HTTPPort = cfg.Local.SocksPort + 1000
	}

	applyDefaults(cfg)
	return cfg, nil
}

func ApplySimpleOverrides(cfg *ClientConfig, s *sharedconfig.SimpleConfig) {
	srv := cfg.DefaultServer()
	if srv != nil {
		if s.Server != "" {
			srv.Address = s.Server
		}
		if s.ServerPort > 0 {
			srv.Port = s.ServerPort
		}
		if s.Password != "" {
			srv.Password = s.Password
		}
		if s.Method != "" {
			srv.Method = s.Method
		}
		if s.SN != "" {
			srv.SNI = s.SN
		}
		if s.CAPath != "" {
			srv.CAPath = s.CAPath
		}
	}
	if s.LocalPort > 0 {
		cfg.Local.SocksPort = s.LocalPort
		if cfg.Local.HTTPPort == 0 {
			cfg.Local.HTTPPort = s.LocalPort + 1000
		}
	}
	if s.HTTPPort > 0 {
		cfg.Local.HTTPPort = s.HTTPPort
	}
	if s.ProxyRule != "" {
		cfg.Routing.ProxyRule = s.ProxyRule
	}
	if s.IPV6Rule != "" {
		cfg.Routing.IPV6Rule = s.IPV6Rule
	}
	if s.DirectFile != "" {
		cfg.Routing.DirectFile = s.DirectFile
	}
	if s.ProxyFile != "" {
		cfg.Routing.ProxyFile = s.ProxyFile
	}
	if s.Timeout > 0 {
		cfg.Timeout = s.Timeout
	}
	if s.LogLevel != "" {
		cfg.Log.Level = s.LogLevel
	}
	if s.LogFilePath != "" {
		cfg.Log.FilePath = s.LogFilePath
	}
	if s.DisableSysProxy {
		cfg.Local.DisableSysProxy = true
	}
	if s.EnableForwardDNS {
		cfg.Local.EnableForwardDNS = true
	}
	if s.EnableTun2socks {
		cfg.Local.EnableTun2socks = true
	}
	if s.EnableQUIC {
		cfg.Local.EnableQUIC = true
	}
	if s.BindAll {
		cfg.Local.BindAll = true
	}
	if s.OutboundProto != "" {
		cfg.Transport.Protocol = "h2"
	}
	if s.TunConfig != "" {
		cfg.Local.TunConfig = jsonTunConfig(s.TunConfig)
	}
}

func jsonTunConfig(s string) json.RawMessage {
	if s == "" {
		return nil
	}
	return json.RawMessage(s)
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
