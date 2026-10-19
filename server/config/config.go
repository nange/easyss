package config

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util"
)

type LogConfig struct {
	Level    string `json:"level"`
	FilePath string `json:"file_path"`
}

// TransportConfig 是服务端的 HTTP/2 传输参数。字段的 0 值一律表示"使用
// sharedconfig 中的默认值"（由 applyDefaults 写回；buildHTTPServer 只对绕过
// 加载、仍为 0 的调用方保留 effectiveH2 兜底），这里不存第二份默认值。
//
// 三个 h2_* 字段都作用在**每一个连接**上（SETTINGS 与连接级 WINDOW_UPDATE 每个
// 连接各一份）。每条连接的并发流上限**不可配**：它固定为
// sharedconfig.HTTP2ServerMaxConcurrentStreams（128），见该常量的说明。
//
// 取值范围与标准库的实际接受区间一致（见 validateTransport）：越界值必须在
// 加载期被拒绝，而不是留给 net/http 静默替换成它自己的 1MiB 默认值。
type TransportConfig struct {
	// H2MaxFrameSize 是服务端愿意接收的最大帧（16KiB~16MiB-1）：客户端据此决定
	// 每个 DATA 帧的大小，调小会把一条加密记录拆成多个帧。
	H2MaxFrameSize int `json:"h2_max_frame_size"`
	// H2RecvBufConn 是连接级上行窗口（字节）。它同时是"已收到但 handler 未读走"的
	// 请求体在**每个连接**上的上界——每个字节都要同时扣减连接与流两个窗口，额度只在
	// handler 读走后返还，因此并发流数不会突破它。这是请求体这一侧的上界，不是该连接
	// 的全部内存：handler 读走之后的数据由下游持有，不受它约束。
	//
	// 它同时是流级窗口的硬上限，因此应 ≥ H2RecvBufStream（更小时单流的在途额度由它
	// 决定，server.buildHTTPServer 会告警）。调大它提升同一连接上的聚合上传上限
	// （例如多流测速），代价是同比例的内存上界。
	H2RecvBufConn int `json:"h2_recv_buf_conn"`
	// H2RecvBufStream 是流级上行窗口（字节），决定单条上传流的吞吐上限
	// （≈ 窗口/RTT）。它不改变服务端的内存上界（那由 H2RecvBufConn 决定）。
	H2RecvBufStream int `json:"h2_recv_buf_stream"`
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
//
// Host 是 ACME 标识符（域名或公网 IPv4 字面量）；Port 是监听端口，默认由
// applyDefaults 写为 443；Bind 是可选的监听网卡地址（不含端口，默认空表示
// 所有网卡），主要承接旧配置 server.listen 的主机部分。
type ServerConfig struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Bind           string   `json:"bind,omitempty"`
	Password       string   `json:"password"`
	AllowedMethods []string `json:"allowed_methods"`
	CertPath       string   `json:"cert_path"`
	KeyPath        string   `json:"key_path"`
	Email          string   `json:"email"`
}

// UnmarshalJSON 兼容 v3 早期配置里的 server.domain 与 server.listen：
// domain 直接映射到 host；listen（":443" 或 "127.0.0.1:443"）拆成 bind+port。
// 新旧键同时出现属于歧义配置，直接报错而不是静默选择其中一个。
func (c *ServerConfig) UnmarshalJSON(data []byte) error {
	type plain ServerConfig
	var pc plain
	if err := json.Unmarshal(data, &pc); err != nil {
		return err
	}

	var legacy struct {
		Domain string `json:"domain"`
		Listen string `json:"listen"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}

	// 旧配置整组使用 domain/listen，新配置整组使用 host/port/bind；混用会让
	// "这个字段到底是旧键还是新键"无法判断，直接拒绝。
	legacyUsed := legacy.Domain != "" || legacy.Listen != ""
	newUsed := pc.Host != "" || pc.Port != 0 || pc.Bind != ""
	if legacyUsed && newUsed {
		return fmt.Errorf(`server: do not mix deprecated "domain"/"listen" with "host"/"port"/"bind"`)
	}

	if legacy.Domain != "" {
		pc.Host = legacy.Domain
	}
	if legacy.Listen != "" {
		host, portStr, err := net.SplitHostPort(legacy.Listen)
		if err != nil {
			return fmt.Errorf("server.listen %q: %w; use server.port in new configs", legacy.Listen, err)
		}
		// 旧 listen 允许服务名端口（如 ":https"），LookupPort 同时接受数字与
		// 服务名，最终统一为数字 Port。
		port, err := net.LookupPort("tcp", portStr)
		if err != nil {
			return fmt.Errorf("server.listen %q: %w; use server.port in new configs", legacy.Listen, err)
		}
		pc.Bind = host
		pc.Port = port
	}

	*c = ServerConfig(pc)
	return nil
}

// ListenAddr 返回 HTTP 服务端实际使用的监听地址：Bind 为空时监听所有网卡，
// 否则只监听指定地址。它是监听地址的唯一格式化入口。Port 为 0 时回退到
// sharedconfig.DefaultServerPort，使绕过 LoadConfig 直接构造配置的调用方
// （测试、嵌入式）不会静默监听随机端口；正常加载路径已由 applyDefaults 写回。
func (c *ServerConfig) ListenAddr() string {
	port := c.Port
	if port == 0 {
		port = sharedconfig.DefaultServerPort
	}
	return net.JoinHostPort(c.Bind, strconv.Itoa(port))
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
//
// 字段改名（domain→host、listen→port/bind）不升版本：旧键仍由
// ServerConfig.UnmarshalJSON 兼容读取，版本 3 的配置在升级前后都能加载。
const SupportedConfigVersion = 3

// LoadConfig 读取并解析服务端配置文件，返回已完成归一化的配置：版本校验、
// applyDefaults、Validate（allowed_methods / h2_* / TLS / 监听端点）与
// ResolveFilePaths 都在这里完成，调用方（cmd/easyss-server）拿到的必然是可直接
// 交给 server.New 的有效配置，不再各自排列这些步骤。
//
// 所有"写错了却不报错"的配置都收口在这里：allowed_methods 的未知值、h2_* 的
// 越界值、端口与 bind 的非法值都在加载期直接失败，而不是被 handler/标准库静默
// 丢弃或替换，或留到 net.Listen 才以难以定位的症状暴露。
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

	// 显式值与默认值在同一处归一化：applyDefaults 写回 timeout/log.level/port
	// 与 h2_*，Validate 只负责拒绝无法归一化的值。在默认值写回之后校验 h2_*
	// 同时守住 sharedconfig 的默认值常量本身——默认值一旦落到标准库接受区间
	// 之外，"没配"也会被静默替换。
	applyDefaults(&fc)
	if err := fc.Validate(); err != nil {
		return nil, err
	}
	// 相对文件路径（证书、代理列表、日志文件）在这里统一解析。
	fc.ResolveFilePaths()

	return &fc, nil
}

// Validate 校验启动前可判定的配置约束：allowed_methods、h2_*、证书来源
// （validateTLS）与监听端点（validateListen）。LoadConfig 与 server.New 共用
// 它——server.New 是导出 API，测试与嵌入式调用会直接手搓 FileConfig，不能只
// 依赖配置文件路径上的校验。
//
// 监听端点的校验使用 ListenAddr 的默认值语义：Port==0 按 sharedconfig
// 的默认端口校验，因此直接构造的 FileConfig 不必先经过 applyDefaults。
func (fc *FileConfig) Validate() error {
	if err := fc.validateAllowedMethods(); err != nil {
		return err
	}
	if err := fc.validateTransport(); err != nil {
		return err
	}
	if err := fc.validateTLS(); err != nil {
		return err
	}
	return fc.validateListenOrDefault()
}

// validateAllowedMethods 拒绝 allowed_methods 里的未知加密方式。
//
// 旧行为是 handler.NewProxyHandler 把无法识别的值静默丢弃（protocol.MethodFromString
// 返回 0），全部写错时过滤结果为空、于是回落到"两种都允许"——一条写错的限制配置
// 反而把服务端放开成接受所有方法，且启动日志没有任何提示。这里在加载期直接失败，
// 让配置错误以它本来的样子暴露。
//
// 空列表仍是文档化的"使用默认对"（见 GetAllowedMethods），不在这里报错。
func (fc *FileConfig) validateAllowedMethods() error {
	for i, name := range fc.Server.AllowedMethods {
		if protocol.MethodFromString(name) == 0 {
			return fmt.Errorf("server.allowed_methods[%d] %q is not a supported method; valid values are %s",
				i, name, strings.Join(DefaultAllowedMethods(), ", "))
		}
	}
	return nil
}

// validateTransport 校验 transport.h2_* 的取值范围，使越界值在加载期报错，而不是
// 被 net/http 在内部静默替换成它自己的默认值。
//
// 边界取标准库**实际**的接受区间（net/http/internal/http2 的 setConfigDefaults）：
//
//   - MaxReadFrameSize: [16KiB, 16MiB-1]；
//   - MaxReceiveBufferPerConnection: [64KiB-1, MaxInt32]（实现以 initialWindowSize
//     65535 为下界）；
//   - MaxReceiveBufferPerStream: [1, MaxInt32]。
//
// 注意文档把两个窗口写成"小于 4MiB"，但实现接受 4MiB..MaxInt32；这里按实现校验，
// 否则 4MiB-1 以上的合法（且被既有测试使用的）配置会被误拒。0 是文档化的
// "使用默认值"，负值则没有语义，一并拒绝。
func (fc *FileConfig) validateTransport() error {
	tr := fc.Transport
	if v := tr.H2MaxFrameSize; v != 0 && (v < h2MinMaxFrameSize || v > h2MaxMaxFrameSize) {
		return fmt.Errorf("transport.h2_max_frame_size %d is out of range [%d, %d] (0 means the default)",
			v, h2MinMaxFrameSize, h2MaxMaxFrameSize)
	}
	if v := tr.H2RecvBufConn; v != 0 && (v < h2MinRecvBufConn || v > math.MaxInt32) {
		return fmt.Errorf("transport.h2_recv_buf_conn %d is out of range [%d, %d] (0 means the default)",
			v, h2MinRecvBufConn, math.MaxInt32)
	}
	if v := tr.H2RecvBufStream; v != 0 && (v < h2MinRecvBufStream || v > math.MaxInt32) {
		return fmt.Errorf("transport.h2_recv_buf_stream %d is out of range [%d, %d] (0 means the default)",
			v, h2MinRecvBufStream, math.MaxInt32)
	}
	return nil
}

// h2_* 的边界与 net/http 内部校验保持一致。它们不是配置默认值（默认值由
// sharedconfig 常量持有），而是"标准库会静默替换"的临界点，因此只在加载期校验
// 中使用。
const (
	h2MinMaxFrameSize  = 1 << 14 // 16KiB，SETTINGS_MAX_FRAME_SIZE 的协议下界
	h2MaxMaxFrameSize  = 1<<24 - 1
	h2MinRecvBufConn   = 1<<16 - 1 // 65535，即 HTTP/2 初始窗口
	h2MinRecvBufStream = 1
)

// applyDefaults 把服务端配置归一化为与运行期消费点一致的有效值，使内存中的
// 配置本身就是有效的，而不是把合法性的判断留给每个消费点。
//
// 它只处理没有其他 owner 的配置策略；其余字段的默认值各有唯一出处，不在这里
// 存第二份副本，否则它们会彼此偏离：
//
//   - shaper.*：默认值与边界由 shaper.Config.Normalize 唯一持有，在
//     handler.NewProxyHandler 构造整形器时应用；
//   - server.allowed_methods：空值语义由 ServerConfig.GetAllowedMethods 负责，
//     它不依赖配置对象的构造路径（测试与嵌入式调用方会直接手搓 FileConfig）；
//   - server.port：0 表示未配置，取 sharedconfig.DefaultServerPort。监听地址的
//     格式化由 ServerConfig.ListenAddr 负责，这里不保存第二份地址。
//
// transport.h2_* 的 0 值在这里写回 sharedconfig 默认值：越界值已由
// validateTransport 拒绝，因此写回之后 buildHTTPServer 看到的就是标准库实际
// 接受的生效值，启动日志也不会再打印"原始但无效"的数字。
func applyDefaults(fc *FileConfig) {
	// timeout 是全部派生超时的唯一旋钮：非正值取默认值，越界值钳制到
	// [MinTimeout, MaxTimeout]。这里把结果写回结构体，使内存中的配置与
	// server.Start 之后派生的值始终一致（见 config.NormalizeTimeout）。
	fc.Timeout = sharedconfig.NormalizeTimeout(fc.Timeout)
	if fc.Log.Level == "" {
		fc.Log.Level = sharedconfig.DefaultLogLevel
	}
	if fc.Server.Port == 0 {
		fc.Server.Port = sharedconfig.DefaultServerPort
	}
	if fc.Transport.H2MaxFrameSize == 0 {
		fc.Transport.H2MaxFrameSize = sharedconfig.HTTP2ServerMaxReadFrameSize
	}
	if fc.Transport.H2RecvBufConn == 0 {
		fc.Transport.H2RecvBufConn = sharedconfig.HTTP2ServerReceiveBufferPerConnection
	}
	if fc.Transport.H2RecvBufStream == 0 {
		fc.Transport.H2RecvBufStream = sharedconfig.HTTP2ServerReceiveBufferPerStream
	}
}

// validateListen 在配置加载阶段固定监听端点的契约：端口必须落在可绑定范围内；
// bind 只接受主机名或 IP 字面量（不含端口与方括号）。这些错误若留到 net.Listen
// 才暴露，症状会变成含义不清的 ": too many colons" 之类。
//
// 它要求 Port 已经是最终值；Port==0 的默认值语义由 validateListenOrDefault
// 与 ServerConfig.ListenAddr 处理。
func (fc *FileConfig) validateListen() error {
	return validateListenEndpoint(fc.Server.Port, fc.Server.Bind)
}

// validateListenOrDefault 用 ListenAddr 相同的默认值语义校验监听端点：Port==0
// 表示 sharedconfig.DefaultServerPort。它供**绕过 LoadConfig（未执行
// applyDefaults）** 的 server.New 调用方使用。
func (fc *FileConfig) validateListenOrDefault() error {
	if fc.Server.Port != 0 {
		return fc.validateListen()
	}
	return validateListenEndpoint(sharedconfig.DefaultServerPort, fc.Server.Bind)
}

// validateListenEndpoint 是 validateListen 与 validateListenOrDefault 的共享
// 实现，只接受已经确定下来的端口值。
func validateListenEndpoint(port int, bind string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("server.port %d is out of range [1, 65535]", port)
	}
	if bind == "" {
		return nil
	}
	if strings.ContainsAny(bind, "[]") {
		return fmt.Errorf("server.bind %q must not contain brackets; write an IPv6 literal as ::1", bind)
	}
	if strings.Contains(bind, ":") {
		if _, err := netip.ParseAddr(bind); err != nil {
			return fmt.Errorf("server.bind %q must be a host name or IP literal without a port", bind)
		}
	}
	return nil
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
// 且其中的默认值全部引用 sharedconfig 常量。必填项（host、password）使用
// 占位符；返回值本身是已归一化的合法配置，可直接交给 server.New。
func ExampleConfig() FileConfig {
	return FileConfig{
		ConfigVersion: SupportedConfigVersion,
		Server: ServerConfig{
			// host 是 ACME 标识符：域名，或**公网 IPv4 字面量**（IP-only 模式，
			// 见 validateTLS 与 README 的"不用域名"一节）。IP-only 时 Let's
			// Encrypt 只发短生命周期（约 160 小时）的 IP 证书，且只能用
			// tls-alpn-01 验证——公网 443 必须可达，每次续期也一样。
			Host: "your-domain.com",
			// port 默认 443，监听所有网卡；需要绑定指定网卡时使用可选字段
			// server.bind。bind 默认为空，因此不会出现在示例里。
			Port:           sharedconfig.DefaultServerPort,
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
