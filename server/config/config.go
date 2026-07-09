package config

type LogConfig struct {
	Level    string `json:"level"`
	FilePath string `json:"file_path"`
}

type TransportConfig struct {
	Protocol       string `json:"protocol"`
	EndpointPrefix string `json:"endpoint_prefix"`
}

type NextProxyConfig struct {
	URL           string `json:"url"`
	NextProxyFile string `json:"next_proxy_file"`
	EnableUDP     bool   `json:"enable_udp"`
	AllHost       bool   `json:"all_host"`
}

type ServerConfig struct {
	Listen           string          `json:"listen"`
	Domain           string          `json:"domain"`
	Password         string          `json:"password"`
	AllowedMethods   []string        `json:"allowed_methods"`
	CertPath         string          `json:"cert_path"`
	KeyPath          string          `json:"key_path"`
	Email            string          `json:"email"`
	FallbackTarget   string          `json:"fallback_target"`
	Timeout          int             `json:"-"`
	BatchWindowMS    int             `json:"batch_window_ms"`
	CoverBudgetRatio float64         `json:"cover_budget_ratio"`
	NextProxy        NextProxyConfig `json:"-"`
	PprofEnabled     bool            `json:"pprof_enabled"`
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

func (c *ServerConfig) GetAllowedMethods() []string {
	if len(c.AllowedMethods) == 0 {
		return []string{"aes-256-gcm", "chacha20-poly1305"}
	}
	return c.AllowedMethods
}
