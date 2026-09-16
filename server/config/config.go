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

// ServerConfig 恰好持有配置文件 "server" 键下的全部字段。顶层设置
// （version、timeout、fallback、shaper、transport、next_proxy、log、
// pprof_enabled）只存在于 FileConfig 上：server.Server 读取这一个结构体，
// 而不是再合并一份副本。
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

// ResolveFilePaths 将配置中的相对文件路径解析为相对可执行文件目录的路径，
// 前提是这些路径无法在当前工作目录中找到。在 macOS 上服务端常由 launchd
// 以 cwd=/ 启动，因此 cert_path/key_path 或 next_proxy_file 等相对路径
// 即使与二进制位于同一目录，也照样无法被找到。
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
