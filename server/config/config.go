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
	Protocol            string `json:"protocol"`
	HTTP2MaxFrameSize   int    `json:"http2_max_frame_size"`
	HTTP2RecvBufConn    int    `json:"http2_recv_buf_conn"`
	HTTP2RecvBufStream  int    `json:"http2_recv_buf_stream"`
	MaxConcurrentStream int    `json:"max_concurrent_streams"`
}

type FallbackConfig struct {
	Target       string   `json:"target"`
	PreserveHost bool     `json:"preserve_host"`
	CDNDomains   []string `json:"cdn_domains"`
}

type ShaperConfig struct {
	BatchWindowMS    int     `json:"batch_window_ms"`
	CoverBudgetRatio float64 `json:"cover_budget_ratio"`
	CoverBudgetCap   int     `json:"cover_budget_cap"`
}

type NextProxyConfig struct {
	URL           string `json:"url"`
	NextProxyFile string `json:"next_proxy_file"`
	EnableUDP     bool   `json:"enable_udp"`
	AllHost       bool   `json:"all_host"`
}

type ServerConfig struct {
	Listen         string          `json:"listen"`
	Domain         string          `json:"domain"`
	Password       string          `json:"password"`
	AllowedMethods []string        `json:"allowed_methods"`
	CertPath       string          `json:"cert_path"`
	KeyPath        string          `json:"key_path"`
	Email          string          `json:"email"`
	Timeout        int             `json:"-"`
	Fallback       FallbackConfig  `json:"-"`
	Shaper         ShaperConfig    `json:"-"`
	Transport      TransportConfig `json:"-"`
	NextProxy      NextProxyConfig `json:"-"`
}

type FileConfig struct {
	ConfigVersion int             `json:"version"`
	Server        ServerConfig    `json:"server"`
	Fallback      FallbackConfig  `json:"fallback"`
	Shaper        ShaperConfig    `json:"shaper"`
	Transport     TransportConfig `json:"transport"`
	NextProxy     NextProxyConfig `json:"next_proxy"`
	Log           LogConfig       `json:"log"`
	PprofEnabled  bool            `json:"pprof_enabled"`
	Timeout       int             `json:"timeout"`
}

func (fc *FileConfig) EffectiveServerConfig() ServerConfig {
	cfg := fc.Server
	cfg.Timeout = fc.Timeout
	cfg.Fallback = fc.Fallback
	cfg.Shaper = fc.Shaper
	cfg.Transport = fc.Transport
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
