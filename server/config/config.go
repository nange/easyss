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
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
)

// 0 值表示"使用 sharedconfig 中的默认值"（由 applyDefaults 写回）。每条连接的并发
// 流上限不可配，固定为 sharedconfig.HTTP2ServerMaxConcurrentStreams。
type TransportConfig struct {
	// H2MaxFrameSize 是服务端愿意接收的最大帧：客户端据此决定每个 DATA 帧的大小，
	// 调小会把一条加密记录拆成多个帧。
	H2MaxFrameSize int `json:"h2_max_frame_size"`
	// H2RecvBufConn 是连接级上行窗口，每个字节同时扣减连接与流两个窗口，额度只在
	// handler 读走后返还。它也是流级窗口的硬上限：小于 H2RecvBufStream 时单流额度由它决定。
	H2RecvBufConn int `json:"h2_recv_buf_conn"`
	// H2RecvBufStream 决定单条上传流的吞吐上限（≈ 窗口/RTT）。
	H2RecvBufStream int `json:"h2_recv_buf_stream"`
}

type FallbackConfig struct {
	Target       string   `json:"target"`
	PreserveHost bool     `json:"preserve_host"`
	CDNDomains   []string `json:"cdn_domains"`
}

type NextProxyConfig struct {
	URL           string `json:"url"`
	NextProxyFile string `json:"next_proxy_file"`
	EnableUDP     bool   `json:"enable_udp"`
	AllHost       bool   `json:"all_host"`
}

// Host 是 ACME 标识符（域名或公网 IPv4 字面量）；Bind 是可选的监听网卡地址，
// 不含端口，空表示所有网卡。
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

// UnmarshalJSON 兼容 server.domain 与 server.listen：domain 映射到 host，
// listen（":443" 或 "127.0.0.1:443"）拆成 bind+port。
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
		// listen 允许服务名端口（如 ":https"），LookupPort 同时接受数字与服务名。
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

// ListenAddr 是监听地址的唯一格式化入口。Port 为 0 时回退到默认端口，绕过
// LoadConfig 的调用方不会静默监听随机端口。
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
	Shaper        shaper.Config   `json:"shaper"`
	Transport     TransportConfig `json:"transport"`
	NextProxy     NextProxyConfig `json:"next_proxy"`
	Log           log.Config      `json:"log"`
	PprofEnabled  bool            `json:"pprof_enabled"`
	Timeout       int             `json:"timeout"`
}

// 为其他主版本编写的配置可能含本二进制会静默忽略或作不同解释的字段，LoadConfig
// 因此拒绝启动。字段改名不升版本，旧键仍由 UnmarshalJSON 兼容读取。
const SupportedConfigVersion = 3

// LoadConfig 依次完成版本校验、applyDefaults、Validate 与 ResolveFilePaths，所有
// "写错了却不报错"的配置都在这里失败。
func LoadConfig(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var fc FileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, err
	}

	// 0 表示该字段不存在。
	if fc.ConfigVersion != 0 && fc.ConfigVersion != SupportedConfigVersion {
		return nil, fmt.Errorf("unsupported config version %d (supported %d)", fc.ConfigVersion, SupportedConfigVersion)
	}

	// 默认值写回后再校验 h2_*，同时守住 sharedconfig 常量：默认值落到标准库接受
	// 区间之外时，"没配"也会被静默替换。
	applyDefaults(&fc)
	if err := fc.Validate(); err != nil {
		return nil, err
	}
	fc.ResolveFilePaths()

	return &fc, nil
}

// Validate 由 LoadConfig 与 server.New 共用：测试与嵌入式调用会直接手搓 FileConfig，
// 不能只依赖配置文件路径上的校验。
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

// validateAllowedMethods 不能依赖运行期过滤：MethodFromString 对无法识别的值返回 0，
// 全部写错时过滤结果为空，于是回落到"两种都允许"，写错的限制反而放开所有方法。
func (fc *FileConfig) validateAllowedMethods() error {
	for i, name := range fc.Server.AllowedMethods {
		if protocol.MethodFromString(name) == 0 {
			return fmt.Errorf("server.allowed_methods[%d] %q is not a supported method; valid values are %s",
				i, name, strings.Join(DefaultAllowedMethods(), ", "))
		}
	}
	return nil
}

// validateTransport 按标准库实际接受的区间校验 h2_*：文档把两个窗口写成"小于 4MiB"，
// 实现却接受 4MiB..MaxInt32，按实现校验才不会被 net/http 静默替换。
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

// h2_* 的边界与 net/http 内部校验保持一致，只在加载期校验中使用。
const (
	h2MinMaxFrameSize  = 1 << 14 // 16KiB，SETTINGS_MAX_FRAME_SIZE 的协议下界
	h2MaxMaxFrameSize  = 1<<24 - 1
	h2MinRecvBufConn   = 1<<16 - 1 // 65535，即 HTTP/2 初始窗口
	h2MinRecvBufStream = 1
)

// applyDefaults 只处理没有其他 owner 的配置策略，其余默认值各有唯一出处，这里不存
// 第二份副本：shaper.* 归 shaper.Config.Normalize，allowed_methods 归 GetAllowedMethods。
func applyDefaults(fc *FileConfig) {
	// timeout 是全部派生超时的唯一旋钮。
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

// validateListen 要求 Port 已是最终值，否则留到 net.Listen 才暴露成 ": too many colons"。
func (fc *FileConfig) validateListen() error {
	return validateListenEndpoint(fc.Server.Port, fc.Server.Bind)
}

func (fc *FileConfig) validateListenOrDefault() error {
	if fc.Server.Port != 0 {
		return fc.validateListen()
	}
	return validateListenEndpoint(sharedconfig.DefaultServerPort, fc.Server.Bind)
}

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

// ResolveFilePaths 把相对文件路径解析为相对可执行文件目录：macOS 上服务端常由
// launchd 以 cwd=/ 启动，与二进制同目录的相对路径照样找不到。
func (fc *FileConfig) ResolveFilePaths() {
	fc.Server.CertPath = util.ResolvePath(fc.Server.CertPath)
	fc.Server.KeyPath = util.ResolvePath(fc.Server.KeyPath)
	fc.NextProxy.NextProxyFile = util.ResolvePath(fc.NextProxy.NextProxyFile)

	// 日志路径基于可执行文件目录绝对化，否则 launchd（cwd=/）会把日志写到根目录。
	if fc.Log.FilePath != "" && !filepath.IsAbs(fc.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			fc.Log.FilePath = filepath.Join(dir, fc.Log.FilePath)
		}
	}
}

func DefaultAllowedMethods() []string {
	return []string{protocol.MethodAES256GCM.String(), protocol.MethodChaCha20Poly1305.String()}
}

func (c *ServerConfig) GetAllowedMethods() []string {
	if len(c.AllowedMethods) == 0 {
		return DefaultAllowedMethods()
	}
	return c.AllowedMethods
}

// ExampleConfig 供 -show-config-example 使用，返回值本身已归一化。
func ExampleConfig() FileConfig {
	return FileConfig{
		ConfigVersion: SupportedConfigVersion,
		Server: ServerConfig{
			// host 是 ACME 标识符：域名或公网 IPv4 字面量。IP-only 时 Let's Encrypt 只发
			// 短生命周期（约 160 小时）的 IP 证书，且只能用 tls-alpn-01 验证。
			Host:           "your-domain.com",
			Port:           sharedconfig.DefaultServerPort,
			Password:       "your-password",
			AllowedMethods: DefaultAllowedMethods(),
		},
		// 显式给出空切片：示例里 cdn_domains 应呈现为 [] 而不是 null。
		Fallback: FallbackConfig{
			CDNDomains: []string{},
		},
		Shaper: shaper.Config{
			BatchWindowMS: sharedconfig.DefaultBatchWindowMS,
			BudgetRatio:   sharedconfig.DefaultCoverBudgetRatio,
			BudgetCap:     sharedconfig.DefaultCoverBudgetCap,
		},
		Transport: TransportConfig{
			H2MaxFrameSize:  sharedconfig.HTTP2ServerMaxReadFrameSize,
			H2RecvBufConn:   sharedconfig.HTTP2ServerReceiveBufferPerConnection,
			H2RecvBufStream: sharedconfig.HTTP2ServerReceiveBufferPerStream,
		},
		Log: log.Config{
			Level:    sharedconfig.DefaultLogLevel,
			FilePath: "easyss.log",
		},
		Timeout: sharedconfig.DefaultTimeout,
	}
}
