package config

import (
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util"
)

type LogConfig struct {
	Level    string `json:"level"`
	FilePath string `json:"file_path"`
}

type TransportConfig struct {
	Protocol string `json:"protocol"`
}

type NextProxyConfig struct {
	URL           string `json:"url"`
	NextProxyFile string `json:"next_proxy_file"`
	EnableUDP     bool   `json:"enable_udp"`
	AllHost       bool   `json:"all_host"`
}

type ServerConfig struct {
	Listen               string          `json:"listen"`
	Domain               string          `json:"domain"`
	Password             string          `json:"password"`
	AllowedMethods       []string        `json:"allowed_methods"`
	CertPath             string          `json:"cert_path"`
	KeyPath              string          `json:"key_path"`
	Email                string          `json:"email"`
	FallbackTarget       string          `json:"fallback_target"`
	FallbackPreserveHost bool            `json:"fallback_preserve_host"`
	FallbackCDNDomains   []string        `json:"fallback_cdn_domains"`
	Timeout              int             `json:"-"`
	BatchWindowMS        int             `json:"batch_window_ms"`
	CoverBudgetRatio     float64         `json:"cover_budget_ratio"`
	CoverBudgetCap       int             `json:"cover_budget_cap"`
	NextProxy            NextProxyConfig `json:"-"`
	PprofEnabled         bool            `json:"pprof_enabled"`
}

type FileConfig struct {
	ConfigVersion int             `json:"version"`
	Server        ServerConfig    `json:"server"`
	Log           LogConfig       `json:"log"`
	Transport     TransportConfig `json:"transport"`
	NextProxy     NextProxyConfig `json:"next_proxy"`
	Timeout       int             `json:"timeout"`
}

func (fc *FileConfig) EffectiveServerConfig() ServerConfig {
	cfg := fc.Server
	cfg.Timeout = fc.Timeout
	cfg.NextProxy = fc.NextProxy
	return cfg
}

// ResolveFilePaths resolves relative file paths in the config against the
// executable directory when they cannot be found in the current working
// directory. Must be called before EffectiveServerConfig since the latter
// copies the Server/NextProxy structs by value. On macOS the server is often
// launched by launchd with cwd=/, so relative paths like cert_path/key_path
// or next_proxy_file would otherwise not be found even though the files sit
// next to the binary.
func (fc *FileConfig) ResolveFilePaths() {
	fc.Server.CertPath = util.ResolvePath(fc.Server.CertPath)
	fc.Server.KeyPath = util.ResolvePath(fc.Server.KeyPath)
	fc.NextProxy.NextProxyFile = util.ResolvePath(fc.NextProxy.NextProxyFile)
}

func (c *ServerConfig) GetAllowedMethods() []string {
	if len(c.AllowedMethods) == 0 {
		return []string{protocol.MethodAES256GCM.String(), protocol.MethodChaCha20Poly1305.String()}
	}
	return c.AllowedMethods
}
