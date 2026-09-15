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
	Protocols       []string `json:"protocols"`
	H2MaxFrameSize  int      `json:"h2_max_frame_size"`
	H2RecvBufConn   int      `json:"h2_recv_buf_conn"`
	H2RecvBufStream int      `json:"h2_recv_buf_stream"`
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

// ServerConfig holds exactly the fields that live under the "server" key of the
// config file. The top-level settings (version, timeout, fallback, shaper,
// transport, next_proxy, log, pprof_enabled) live on FileConfig, their only
// home: server.Server reads that one struct instead of merging a second copy.
type ServerConfig struct {
	Listen         string   `json:"listen"`
	Domain         string   `json:"domain"`
	Password       string   `json:"password"`
	AllowedMethods []string `json:"allowed_methods"`
	CertPath       string   `json:"cert_path"`
	KeyPath        string   `json:"key_path"`
	Email          string   `json:"email"`
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

// ResolveFilePaths resolves relative file paths in the config against the
// executable directory when they cannot be found in the current working
// directory. On macOS the server is often launched by launchd with cwd=/, so
// relative paths like cert_path/key_path or next_proxy_file would otherwise not
// be found even though the files sit next to the binary.
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
