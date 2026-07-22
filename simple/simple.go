package simple

import (
	"fmt"

	"github.com/nange/easyss/v3/client/config"
)

type SimpleConfig struct {
	Server     string
	ServerPort int
	Password   string
	LocalPort  int
	Method     string
	ProxyRule  string
	Timeout    int
	LogLevel   string
	DirectFile string
	ProxyFile  string
	SNI        string
	IPV6Rule   string
	BindAll    bool
	EnableQUIC bool
}

func New() *SimpleConfig {
	return &SimpleConfig{
		ServerPort: 443,
		LocalPort:  2080,
		Method:     "aes-256-gcm",
		ProxyRule:  "auto",
		Timeout:    30,
		LogLevel:   "info",
		IPV6Rule:   "auto",
	}
}

func (s *SimpleConfig) Build() (*config.ClientConfig, error) {
	if s.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if s.Password == "" {
		return nil, fmt.Errorf("password is required")
	}
	if s.ServerPort <= 0 {
		return nil, fmt.Errorf("server_port is required")
	}

	cfg := config.DefaultConfig()

	srv := &config.ServerProfile{
		Address:  s.Server,
		Port:     s.ServerPort,
		Password: s.Password,
		Default:  true,
	}
	if s.Method != "" {
		srv.Method = s.Method
	}
	if s.SNI != "" {
		srv.SNI = s.SNI
	}
	cfg.Servers = []*config.ServerProfile{srv}

	if s.LocalPort > 0 {
		cfg.Local.SocksPort = s.LocalPort
	}
	if cfg.Local.HTTPPort == 0 {
		cfg.Local.HTTPPort = cfg.Local.SocksPort + 1000
	}
	if s.ProxyRule != "" {
		cfg.Routing.ProxyRule = s.ProxyRule
	}
	if s.Timeout > 0 {
		cfg.Timeout = s.Timeout
	}
	if s.LogLevel != "" {
		cfg.Log.Level = s.LogLevel
	}
	if s.DirectFile != "" {
		cfg.Routing.DirectFile = s.DirectFile
	}
	if s.ProxyFile != "" {
		cfg.Routing.ProxyFile = s.ProxyFile
	}
	if s.IPV6Rule != "" {
		cfg.Routing.IPV6Rule = s.IPV6Rule
	}
	if s.BindAll {
		cfg.Local.BindAll = true
	}
	if s.EnableQUIC {
		cfg.Local.EnableQUIC = true
	}

	return cfg, nil
}

func (s *SimpleConfig) ApplyTo(cfg *config.ClientConfig) {
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
		if s.SNI != "" {
			srv.SNI = s.SNI
		}
	}
	if s.LocalPort > 0 {
		cfg.Local.SocksPort = s.LocalPort
		if cfg.Local.HTTPPort == 0 {
			cfg.Local.HTTPPort = s.LocalPort + 1000
		}
	}
	if s.ProxyRule != "" {
		cfg.Routing.ProxyRule = s.ProxyRule
	}
	if s.Timeout > 0 {
		cfg.Timeout = s.Timeout
	}
	if s.LogLevel != "" {
		cfg.Log.Level = s.LogLevel
	}
	if s.DirectFile != "" {
		cfg.Routing.DirectFile = s.DirectFile
	}
	if s.ProxyFile != "" {
		cfg.Routing.ProxyFile = s.ProxyFile
	}
	if s.IPV6Rule != "" {
		cfg.Routing.IPV6Rule = s.IPV6Rule
	}
	if s.BindAll {
		cfg.Local.BindAll = true
	}
	if s.EnableQUIC {
		cfg.Local.EnableQUIC = true
	}
}
