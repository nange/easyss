package config

import (
	"encoding/json"
	"fmt"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/shaper"
)

func BuildSimpleConfig(s *sharedconfig.SimpleConfig) (*ClientConfig, error) {
	if s.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if s.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	proto, err := OutboundProtoToProtocol(s.OutboundProto)
	if err != nil {
		return nil, err
	}
	tunConfig, err := jsonTunConfig(s.TunConfig)
	if err != nil {
		return nil, err
	}

	cfg := &ClientConfig{
		ConfigVersion: 3,
		Servers: []*ServerProfile{{
			Host:     s.Server,
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
			TunMTU:           s.TunMTU,
			TunConfig:        tunConfig,
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
		Shaper: shaper.Config{
			BatchWindowMS: sharedconfig.DefaultBatchWindowMS,
		},
		Log: log.Config{
			Level:    s.LogLevel,
			FilePath: s.LogFilePath,
		},
		Timeout: s.Timeout,
	}

	if cfg.Servers[0].Port == 0 {
		cfg.Servers[0].Port = sharedconfig.DefaultServerPort
	}
	if cfg.Servers[0].Method == "" {
		cfg.Servers[0].Method = sharedconfig.DefaultMethod
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = sharedconfig.DefaultLogLevel
	}
	if cfg.Routing.ProxyRule == "" {
		cfg.Routing.ProxyRule = sharedconfig.DefaultProxyRule
	}
	if cfg.Routing.IPV6Rule == "" {
		cfg.Routing.IPV6Rule = sharedconfig.DefaultIPV6Rule
	}
	// http_port 的推导（socks_port + DefaultHTTPPortOffset）在 applyDefaults 里，
	// 两种模式共用同一实现；这里显式传进来的 HTTPPort 优先，不会被推导覆盖。

	applyDefaults(cfg)
	if err := cfg.validateServers(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// 覆盖后必须再过一次 validateServers：命令行同样可能把端口写进 host（-s example.com:443），
// 不校验就会拼出 https://example.com:443:443 这种要等到拨号才暴露的错误。
func ApplySimpleOverrides(cfg *ClientConfig, s *sharedconfig.SimpleConfig) error {
	srv := cfg.DefaultServer()
	if srv != nil {
		if s.Server != "" {
			srv.Host = s.Server
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
		// 命令行/简单模式覆盖同样要过归一化：它是全部派生超时的唯一旋钮。
		cfg.Timeout = sharedconfig.NormalizeTimeout(s.Timeout)
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
	if s.TunMTU > 0 {
		// 与上面的 timeout 同理：覆盖值也要过唯一的归一化入口。
		cfg.Local.TunMTU = sharedconfig.NormalizeTunMTU(s.TunMTU)
	}
	if s.BindAll {
		cfg.Local.BindAll = true
	}
	if s.TunConfig != "" {
		tunConfig, err := jsonTunConfig(s.TunConfig)
		if err != nil {
			return err
		}
		cfg.Local.TunConfig = tunConfig
	}

	// 覆盖完成后再补齐 http_port，与 applyDefaults 共用唯一实现 normalizeHTTPPort。
	normalizeHTTPPort(cfg)

	return cfg.validateServers()
}

// jsonTunConfig 把简化模式里的 tun_config 字符串转成 RawMessage。消费点只认合法 JSON，
// 写错时会静默退回默认值（例如自定义设备名失效），因此在加载阶段就拒绝。
func jsonTunConfig(s string) (json.RawMessage, error) {
	if s == "" {
		return nil, nil
	}
	if !json.Valid([]byte(s)) {
		return nil, fmt.Errorf("tun_config is not valid JSON: %q", s)
	}
	return json.RawMessage(s), nil
}

func OutboundProtoToProtocol(proto string) (string, error) {
	switch proto {
	case "", "native":
		return sharedconfig.DefaultProtocol, nil
	case sharedconfig.DefaultProtocol:
		return sharedconfig.DefaultProtocol, nil
	default:
		return "", fmt.Errorf("invalid outbound_proto %q: valid values are empty, native, h2", proto)
	}
}
