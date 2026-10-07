package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	sharedconfig "github.com/nange/easyss/v3/config"
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
	Listen         string    `json:"listen"`
	Domain         string    `json:"domain"`
	Password       string    `json:"password"`
	AllowedMethods []string  `json:"allowed_methods"`
	CertPath       string    `json:"cert_path"`
	KeyPath        string    `json:"key_path"`
	Email          string    `json:"email"`
	VPN            VPNConfig `json:"vpn"`
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

// SupportedConfigVersion 是本二进制理解的服务端配置版本。为其他主版本编写的
// 配置可能包含本二进制会静默忽略（或作不同解释）的字段，因此 LoadConfig 会
// 拒绝基于它启动。
const SupportedConfigVersion = 3

// LoadConfig 读取并解析服务端配置文件，返回已完成归一化的配置：版本校验、
// applyDefaults 与 ResolveFilePaths 都在这里完成，调用方（cmd/easyss-server）
// 拿到的必然是可直接交给 server.New 的有效配置，不再各自排列这些步骤。
func LoadConfig(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var fc FileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, err
	}

	// 0 表示该字段不存在（早于该字段的配置），按未设置处理。
	if fc.ConfigVersion != 0 && fc.ConfigVersion != SupportedConfigVersion {
		return nil, fmt.Errorf("unsupported config version %d (supported %d)", fc.ConfigVersion, SupportedConfigVersion)
	}

	applyDefaults(&fc)
	// VPN 的启动期契约（derp_path 形态、derp_addr 可推导或可解析）在这里固定，
	// 且只在 vpn.enabled 时生效：未启用的 VPN 配置不参与运行期。
	if err := fc.validateVPN(); err != nil {
		return nil, err
	}
	// 相对文件路径（证书、代理列表、日志文件）在这里统一解析。
	fc.ResolveFilePaths()

	return &fc, nil
}

// applyDefaults 把服务端配置归一化为与运行期消费点一致的有效值，使内存中的
// 配置本身就是有效的，而不是把合法性的判断留给每个消费点。
//
// 它只处理没有其他 owner 的配置策略，其余字段的默认值各有唯一出处，在这里
// 再存一份副本正是它们会彼此偏离的原因：
//
//   - transport.h2_*：默认值由 sharedconfig 常量持有，"0 使用默认值"是
//     文档化的字段语义，由 server.buildHTTPServer 就地兜底；
//   - shaper.*：默认值与边界由 shaper.Config.Normalize 唯一持有，在
//     handler.NewProxyHandler 构造整形器时应用；
//   - server.allowed_methods：空值语义由 ServerConfig.GetAllowedMethods 负责，
//     它不依赖配置对象的构造路径（测试与嵌入式调用方会直接手搓 FileConfig）。
func applyDefaults(fc *FileConfig) {
	// timeout 是全部派生超时的唯一旋钮：非正值取默认值，越界值钳制到
	// [MinTimeout, MaxTimeout]。这里把结果写回结构体，使内存中的配置与
	// server.Start 之后派生的值始终一致（见 config.NormalizeTimeout）。
	fc.Timeout = sharedconfig.NormalizeTimeout(fc.Timeout)
	if fc.Log.Level == "" {
		fc.Log.Level = sharedconfig.DefaultLogLevel
	}
}

// ResolveFilePaths 将配置中的相对文件路径解析为相对可执行文件目录的路径，
// 前提是这些路径无法在当前工作目录中找到。在 macOS 上服务端常由 launchd
// 以 cwd=/ 启动，因此 cert_path/key_path、next_proxy_file 或 log.file_path
// 等相对路径即使与二进制位于同一目录，也照样无法被找到。
func (fc *FileConfig) ResolveFilePaths() {
	fc.Server.CertPath = util.ResolvePath(fc.Server.CertPath)
	fc.Server.KeyPath = util.ResolvePath(fc.Server.KeyPath)
	fc.NextProxy.NextProxyFile = util.ResolvePath(fc.NextProxy.NextProxyFile)

	// 日志文件路径没有"当前工作目录已存在同名文件则保留"的向后兼容语义
	// （见 util.ResolvePath）：它一律基于可执行文件目录绝对化，否则 launchd
	// （cwd=/）会把日志写到根目录，或在只读目录下直接失败。
	if fc.Log.FilePath != "" && !filepath.IsAbs(fc.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			fc.Log.FilePath = filepath.Join(dir, fc.Log.FilePath)
		}
	}
}

// DefaultAllowedMethods 返回 allowed_methods 留空时允许的加密方式。运行期兜底
// （GetAllowedMethods）与配置示例（ExampleConfig）共用它，因此默认值只有一处
// 定义。每次返回新切片，调用方可以安全改写。
func DefaultAllowedMethods() []string {
	return []string{protocol.MethodAES256GCM.String(), protocol.MethodChaCha20Poly1305.String()}
}

// GetAllowedMethods 返回生效的加密方式列表：allowed_methods 留空时回退到默认对。
func (c *ServerConfig) GetAllowedMethods() []string {
	if len(c.AllowedMethods) == 0 {
		return DefaultAllowedMethods()
	}
	return c.AllowedMethods
}

// ExampleConfig 返回 -show-config-example 展示的完整配置示例。它放在这里而不是
// 留在 cmd/easyss-server：示例与 FileConfig 的定义相邻，新增字段时容易发现遗漏，
// 且其中的默认值全部引用 sharedconfig 常量。必填项（domain、password）使用
// 占位符；返回值本身是已归一化的合法配置，可直接交给 server.New。
func ExampleConfig() FileConfig {
	return FileConfig{
		ConfigVersion: SupportedConfigVersion,
		Server: ServerConfig{
			Listen:         ":443",
			Domain:         "your-domain.com",
			Password:       "your-password",
			AllowedMethods: DefaultAllowedMethods(),
			// DERP 的对外 host:port 与 listen/domain 一致时本可以省略
			// derp_addr（ResolveDERPAddr 会推导），示例里仍然写全：示例是
			// 字段清单，任何新增字段都不应静默漏在示例之外。
			//
			// enabled 默认给 false：内嵌 DERP 虽然只对回环来源提供服务（节点
			// 经 easyss 隧道抵达，公网上没有任何 DERP 路径），但它会把该服务端
			// 变成节点组网的中继，运维应当明确地打开它。
			VPN: VPNConfig{
				Enabled:  false,
				DERPAddr: "your-domain.com:443",
			},
		},
		// 显式给出空切片而不是留 nil：示例里 cdn_domains 应呈现为 []，
		// 与 README 表格中"默认值 []"一致，而不是序列化成 null。
		Fallback: FallbackConfig{
			CDNDomains: []string{},
		},
		Shaper: ShaperConfig{
			BatchWindowMS:    sharedconfig.DefaultBatchWindowMS,
			CoverBudgetRatio: sharedconfig.DefaultCoverBudgetRatio,
			CoverBudgetCap:   sharedconfig.DefaultCoverBudgetCap,
		},
		Transport: TransportConfig{
			Protocols:       []string{sharedconfig.DefaultProtocol},
			H2MaxFrameSize:  sharedconfig.HTTP2ServerMaxReadFrameSize,
			H2RecvBufConn:   sharedconfig.HTTP2ServerReceiveBufferPerConnection,
			H2RecvBufStream: sharedconfig.HTTP2ServerReceiveBufferPerStream,
		},
		Log: LogConfig{
			Level:    sharedconfig.DefaultLogLevel,
			FilePath: "easyss.log",
		},
		Timeout: sharedconfig.DefaultTimeout,
	}
}
