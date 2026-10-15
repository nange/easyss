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

// TransportConfig 是服务端的 HTTP/2 传输参数。字段的 0 值一律表示"使用
// sharedconfig 中的默认值"（由 server.buildHTTPServer 就地兜底），这里不存
// 第二份默认值。
//
// 四个 h2_* 字段都作用在**每一个连接**上（SETTINGS 与连接级 WINDOW_UPDATE 每个
// 连接各一份），其中 h2_max_concurrent_streams 是"每条连接允许的并发流数"，
// 不是服务器级总量。
type TransportConfig struct {
	Protocols []string `json:"protocols"`
	// H2MaxFrameSize 是服务端愿意接收的最大帧（16KiB~16MiB）：客户端据此决定
	// 每个 DATA 帧的大小，调小会把一条加密记录拆成多个帧。
	H2MaxFrameSize int `json:"h2_max_frame_size"`
	// H2RecvBufConn 是连接级上行窗口（字节）。它同时是"已收到但 handler 未读走"
	// 的请求体在**每个连接**上的上界——每个字节都要同时扣减连接与流两个窗口，
	// 额度只在 handler 读走后返还，因此并发流数不会突破它。调大它提升同一连接上
	// 的聚合上传上限（例如多流测速），代价是同比例的内存上界。
	H2RecvBufConn int `json:"h2_recv_buf_conn"`
	// H2RecvBufStream 是流级上行窗口（字节），决定单条上传流的吞吐上限
	// （≈ 窗口/RTT）。它不改变服务端的内存上界（那由 H2RecvBufConn 决定）。
	H2RecvBufStream int `json:"h2_recv_buf_stream"`
	// H2MaxConcurrentStreams 是每条连接允许的并发流数：超限时服务端拒绝那条流
	// （RST_STREAM）而不是断开连接，并限制该连接并发运行的 handler 数。
	// Go stdlib 默认 250，主流站点多为 100/128。
	H2MaxConcurrentStreams int `json:"h2_max_concurrent_streams"`
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

// SupportedConfigVersion 是本二进制理解的服务端配置版本。为其他主版本编写的
// 配置可能包含本二进制会静默忽略（或作不同解释）的字段，因此 LoadConfig 会
// 拒绝基于它启动。
const SupportedConfigVersion = 3

// LoadConfig 读取并解析服务端配置文件，返回已完成归一化的配置：版本校验、
// applyDefaults、validateTLS 与 ResolveFilePaths 都在这里完成，调用方
// （cmd/easyss-server）拿到的必然是可直接交给 server.New 的有效配置，不再各自
// 排列这些步骤。
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
	// 取证书的方式（手工证书 vs Let's Encrypt ACME）在这里固定：证书文件只配了
	// 一半、以及 IP-only 模式写了个不可公网签发的地址，都在启动时明确报错。
	if err := fc.validateTLS(); err != nil {
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
// 留在 cmd/easyss-server：示例与 FileConfig 的定义相邻，新增字段时容易遗漏，
// 且其中的默认值全部引用 sharedconfig 常量。必填项（domain、password）使用
// 占位符；返回值本身是已归一化的合法配置，可直接交给 server.New。
func ExampleConfig() FileConfig {
	return FileConfig{
		ConfigVersion: SupportedConfigVersion,
		Server: ServerConfig{
			Listen: ":443",
			// domain 是 ACME 标识符：域名，或**公网 IPv4 字面量**（IP-only 模式，
			// 见 validateTLS 与 README 的"不用域名"一节）。IP-only 时 Let's
			// Encrypt 只发短生命周期（约 160 小时）的 IP 证书，且只能用
			// tls-alpn-01 验证——公网 443 必须可达，每次续期也一样。
			Domain:         "your-domain.com",
			Password:       "your-password",
			AllowedMethods: DefaultAllowedMethods(),
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
			Protocols:              []string{sharedconfig.DefaultProtocol},
			H2MaxFrameSize:         sharedconfig.HTTP2ServerMaxReadFrameSize,
			H2RecvBufConn:          sharedconfig.HTTP2ServerReceiveBufferPerConnection,
			H2RecvBufStream:        sharedconfig.HTTP2ServerReceiveBufferPerStream,
			H2MaxConcurrentStreams: sharedconfig.HTTP2ServerMaxConcurrentStreams,
		},
		Log: LogConfig{
			Level:    sharedconfig.DefaultLogLevel,
			FilePath: "easyss.log",
		},
		Timeout: sharedconfig.DefaultTimeout,
	}
}
