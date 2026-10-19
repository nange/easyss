package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util"
)

// writeConfig 把配置 JSON 写入临时文件，返回其路径。
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// TestLoadConfigAppliesDefaults 固定 LoadConfig 的契约：调用方拿到的配置已经
// 归一化（timeout 写回、log.level 与 server.port 取常量默认值）且相对文件路径
// 已解析，因此 cmd/easyss-server 不再需要自己排列这些步骤。
func TestLoadConfigAppliesDefaults(t *testing.T) {
	fc, err := LoadConfig(writeConfig(t, `{"server":{"cert_path":"server.crt","key_path":"server.key"},"log":{"file_path":"logs/easyss.log"}}`))
	require.NoError(t, err)

	require.Equal(t, sharedconfig.DefaultTimeout, fc.Timeout)
	require.Equal(t, sharedconfig.DefaultLogLevel, fc.Log.Level)
	require.Equal(t, sharedconfig.DefaultServerPort, fc.Server.Port)
	if want := filepath.Join(util.CurrentDir(), "server.crt"); fc.Server.CertPath != want {
		t.Errorf("CertPath = %q, want %q", fc.Server.CertPath, want)
	}
	if want := filepath.Join(util.CurrentDir(), "logs", "easyss.log"); fc.Log.FilePath != want {
		t.Errorf("Log.FilePath = %q, want %q", fc.Log.FilePath, want)
	}
}

// TestLoadConfigClampsTimeout 固定 timeout 的归一化在配置层就完成并写回结构体：
// 内存中的配置与 server.Start 之后派生的值必须一致，不能留下原始值。
func TestLoadConfigClampsTimeout(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, sharedconfig.DefaultTimeout},
		{-5, sharedconfig.DefaultTimeout},
		{sharedconfig.MinTimeout - 1, sharedconfig.MinTimeout},
		{sharedconfig.MaxTimeout + 1, sharedconfig.MaxTimeout},
		{45, 45},
	}

	for _, tc := range cases {
		fc, err := LoadConfig(writeConfig(t, fmt.Sprintf(`{"server":{"host":"example.com"},"timeout":%d}`, tc.in)))
		require.NoError(t, err)
		if fc.Timeout != tc.want {
			t.Errorf("timeout %d -> %d, want %d", tc.in, fc.Timeout, tc.want)
		}
	}
}

// TestLoadConfigRejectsUnsupportedVersion 固定版本校验的位置与宽容度：其他主版本
// 的配置被拒绝，而版本字段缺失（0）与当前版本都被接受。域名/证书的必填校验是另一
// 道闸（见 TestLoadConfigValidatesTLS），因此这里的夹具给出一份合法的取证配置。
func TestLoadConfigRejectsUnsupportedVersion(t *testing.T) {
	_, err := LoadConfig(writeConfig(t, `{"version":2,"server":{"host":"example.com"}}`))
	require.ErrorContains(t, err, "unsupported config version")

	for _, body := range []string{
		`{"server":{"host":"example.com"}}`,
		fmt.Sprintf(`{"version":%d,"server":{"host":"example.com"}}`, SupportedConfigVersion),
	} {
		_, err := LoadConfig(writeConfig(t, body))
		require.NoError(t, err, "body %s", body)
	}
}

func TestLoadConfigReadAndParseErrors(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)

	_, err = LoadConfig(writeConfig(t, `{"server":`))
	require.Error(t, err)
}

// TestLoadConfigRejectsUnknownAllowedMethods 固定 allowed_methods 的加载期校验：
// 未知值不再被 handler 静默丢弃，更不允许"全部写错 → 回落到两种都允许"的
// fail-open 行为。空列表仍是文档化的默认对。
func TestLoadConfigRejectsUnknownAllowedMethods(t *testing.T) {
	for _, body := range []string{
		`["aes-gcm"]`,
		`["aes-256-gcm-typo"]`,
		`["AES-256-GCM"]`,
		`["aes-256-gcm","foo"]`,
		`[""]`,
	} {
		cfg := fmt.Sprintf(`{"server":{"host":"example.com","allowed_methods":%s}}`, body)
		_, err := LoadConfig(writeConfig(t, cfg))
		require.ErrorContains(t, err, "server.allowed_methods", "allowed_methods %s", body)
	}

	// 合法值（含空列表）必须照常加载：空列表由 GetAllowedMethods 回落默认对。
	fc, err := LoadConfig(writeConfig(t, `{"server":{"host":"example.com","allowed_methods":["aes-256-gcm"]}}`))
	require.NoError(t, err)
	require.Equal(t, []string{"aes-256-gcm"}, fc.Server.AllowedMethods)

	fc, err = LoadConfig(writeConfig(t, `{"server":{"host":"example.com"}}`))
	require.NoError(t, err)
	require.Equal(t, DefaultAllowedMethods(), fc.Server.GetAllowedMethods())
}

// TestLoadConfigRejectsOutOfRangeH2 固定 h2_* 的加载期边界：标准库会把越界值
// 静默替换成它自己的 1MiB 默认值，因此这些值必须在加载期失败，而不是留下
// "日志打印原始值、实际生效另一套"的配置。边界取标准库实际接受区间。
func TestLoadConfigRejectsOutOfRangeH2(t *testing.T) {
	cases := []struct {
		key  string
		vals []int
	}{
		{"h2_max_frame_size", []int{-1, 1<<14 - 1, 1<<24 - 1 + 1}},
		{"h2_recv_buf_conn", []int{-1, 1, 1<<16 - 2}},
		{"h2_recv_buf_stream", []int{-1}},
	}
	for _, tc := range cases {
		for _, v := range tc.vals {
			body := fmt.Sprintf(`{"server":{"host":"example.com"},"transport":{%q:%d}}`, tc.key, v)
			_, err := LoadConfig(writeConfig(t, body))
			require.ErrorContains(t, err, "transport."+tc.key, "%s=%d", tc.key, v)
		}
	}

	// 边界值与 4MiB 以上的窗口（标准库实现接受、既有测试也在用）必须通过。
	for _, body := range []string{
		`{"server":{"host":"example.com"},"transport":{"h2_max_frame_size":16384}}`,
		`{"server":{"host":"example.com"},"transport":{"h2_max_frame_size":16777215}}`,
		`{"server":{"host":"example.com"},"transport":{"h2_recv_buf_conn":65535}}`,
		`{"server":{"host":"example.com"},"transport":{"h2_recv_buf_conn":8388608}}`,
		`{"server":{"host":"example.com"},"transport":{"h2_recv_buf_stream":1}}`,
		`{"server":{"host":"example.com"},"transport":{"h2_recv_buf_stream":8388608}}`,
	} {
		_, err := LoadConfig(writeConfig(t, body))
		require.NoError(t, err, "body %s", body)
	}
}

// TestLoadConfigNormalizesH2Defaults 固定"0 使用默认值"在加载期写回：加载后的
// 配置里是 sharedconfig 的默认值，而不是 0——启动日志与 buildHTTPServer 因此
// 看到的是同一个生效值。
func TestLoadConfigNormalizesH2Defaults(t *testing.T) {
	fc, err := LoadConfig(writeConfig(t, `{"server":{"host":"example.com"}}`))
	require.NoError(t, err)
	require.Equal(t, sharedconfig.HTTP2ServerMaxReadFrameSize, fc.Transport.H2MaxFrameSize)
	require.Equal(t, sharedconfig.HTTP2ServerReceiveBufferPerConnection, fc.Transport.H2RecvBufConn)
	require.Equal(t, sharedconfig.HTTP2ServerReceiveBufferPerStream, fc.Transport.H2RecvBufStream)
}

// TestLoadConfigIgnoresRemovedTransportProtocols 固定"删除 transport.protocols"
// 的向后兼容：老配置里仍带着该键时必须照常启动（未知字段被忽略），实际协议
// 集合由 buildHTTPServer 决定（h2 强制、h1 供 fallback 使用）。
func TestLoadConfigIgnoresRemovedTransportProtocols(t *testing.T) {
	fc, err := LoadConfig(writeConfig(t, `{
		"server": {"host": "example.com"},
		"transport": {"protocols": ["h2"], "h2_recv_buf_stream": 2097152}
	}`))
	require.NoError(t, err)
	require.Equal(t, 2097152, fc.Transport.H2RecvBufStream)
}

// TestApplyDefaultsIsIdempotent 守护"已归一化的配置再次归一化不变"，也固定它
// 只覆盖没有其他 owner 的字段：显式配置的日志级别必须原样保留。
func TestApplyDefaultsIsIdempotent(t *testing.T) {
	fc := FileConfig{Timeout: sharedconfig.MaxTimeout + 1, Log: LogConfig{Level: "debug"}}
	applyDefaults(&fc)

	require.Equal(t, sharedconfig.MaxTimeout, fc.Timeout)
	require.Equal(t, "debug", fc.Log.Level)
	require.Equal(t, sharedconfig.DefaultServerPort, fc.Server.Port)

	once := fc
	applyDefaults(&fc)
	require.Equal(t, once, fc)
}

// TestExampleConfigIsNormalized 固定 -show-config-example 展示的示例本身就是一份
// 已归一化的合法配置：文档中的默认值与运行期默认值不会各自漂移。
func TestExampleConfigIsNormalized(t *testing.T) {
	fc := ExampleConfig()

	normalized := fc
	applyDefaults(&normalized)
	require.Equal(t, fc, normalized)

	require.Equal(t, DefaultAllowedMethods(), fc.Server.AllowedMethods)
	require.Equal(t, SupportedConfigVersion, fc.ConfigVersion)
	require.Equal(t, "your-domain.com", fc.Server.Host)
	require.Equal(t, sharedconfig.DefaultServerPort, fc.Server.Port)
	require.NoError(t, fc.validateListen())
	require.NoError(t, fc.validateTransport())
	require.NoError(t, fc.validateAllowedMethods())

	// 示例必须能完整序列化出全部字段（新增字段时不会静默漏在示例之外；
	// bind 是可选高级项，默认为空，故不出现在示例中），且空列表呈现为 []
	// （与 README 的"默认值 []"一致），不是 null。
	data, err := json.Marshal(fc)
	require.NoError(t, err)
	require.Contains(t, string(data), `"cdn_domains":[]`)
	for _, key := range []string{
		`"server"`, `"fallback"`, `"shaper"`, `"transport"`,
		`"next_proxy"`, `"log"`, `"pprof_enabled"`, `"timeout"`,
		`"host"`, `"port"`,
		// HTTP/2 上行参数必须在示例里可见：用户排查上传速度时就是照这些键调。
		`"h2_max_frame_size"`, `"h2_recv_buf_conn"`, `"h2_recv_buf_stream"`,
	} {
		require.Contains(t, string(data), key)
	}
	require.NotContains(t, string(data), `"domain"`)
	require.NotContains(t, string(data), `"listen"`)
	require.NotContains(t, string(data), `"address"`)
}

// TestTransportConfigH2KeysJSON 固定 HTTP/2 传输键的对外名字与"显式值原样保留"
// 的语义（README 表格、-show-config-example 与配置解析共用这一组键名）。
func TestTransportConfigH2KeysJSON(t *testing.T) {
	var fc FileConfig
	require.NoError(t, json.Unmarshal([]byte(`{
		"transport": {
			"h2_max_frame_size": 65536,
			"h2_recv_buf_conn": 8388608,
			"h2_recv_buf_stream": 2097152
		}
	}`), &fc))

	require.Equal(t, 65536, fc.Transport.H2MaxFrameSize)
	require.Equal(t, 8388608, fc.Transport.H2RecvBufConn)
	require.Equal(t, 2097152, fc.Transport.H2RecvBufStream)
}

// TestLoadConfigIgnoresRemovedH2MaxConcurrentStreams 固定"删除
// h2_max_concurrent_streams 键"是向后兼容的：老配置里仍带着它时必须照常启动
// （未知字段被忽略），并发流上限固定由 sharedconfig.HTTP2ServerMaxConcurrentStreams
// 决定，不能再被配置改写。
func TestLoadConfigIgnoresRemovedH2MaxConcurrentStreams(t *testing.T) {
	fc, err := LoadConfig(writeConfig(t, `{
		"server": {"cert_path": "server.crt", "key_path": "server.key"},
		"transport": {"h2_max_concurrent_streams": 64, "h2_recv_buf_stream": 2097152}
	}`))
	require.NoError(t, err)
	// 其余传输键照常生效；被删除的那个键既不报错也不留下任何痕迹。
	require.Equal(t, 2097152, fc.Transport.H2RecvBufStream)
}

// TestDefaultAllowedMethods 固定默认加密方式列表，并守护每次返回新切片，
// 避免调用方改写后污染其他调用者。
func TestDefaultAllowedMethods(t *testing.T) {
	want := []string{
		protocol.MethodAES256GCM.String(),
		protocol.MethodChaCha20Poly1305.String(),
	}
	got := DefaultAllowedMethods()
	require.Equal(t, want, got)

	got[0] = "mutated"
	require.Equal(t, want, DefaultAllowedMethods())
	require.Equal(t, want, (&ServerConfig{}).GetAllowedMethods())
}

// TestFileConfigJSON 固定文档化的配置形态：顶层设置位于 FileConfig 上，
// "server" 键映射到 ServerConfig，两者之间没有重复字段。
func TestFileConfigJSON(t *testing.T) {
	data := []byte(`{
			"version": 3,
		"server": {
			"port": 443,
			"host": "example.com",
			"password": "secret",
			"allowed_methods": ["aes-256-gcm"],
			"timeout": 99,
			"next_proxy": {"url": "socks5://127.0.0.1:9999", "enable_udp": false}
		},
		"fallback": {"target": "fallback.html"},
		"next_proxy": {"url": "socks5://127.0.0.1:1080", "enable_udp": true},
		"pprof_enabled": true,
		"timeout": 30
	}`)

	var fc FileConfig
	require.NoError(t, json.Unmarshal(data, &fc))
	require.Equal(t, "example.com", fc.Server.Host)
	require.Equal(t, 443, fc.Server.Port)
	require.Empty(t, fc.Server.Bind)
	require.Equal(t, "secret", fc.Server.Password)
	require.Equal(t, []string{"aes-256-gcm"}, fc.Server.AllowedMethods)
	require.Equal(t, "fallback.html", fc.Fallback.Target)
	require.Equal(t, 30, fc.Timeout)
	require.Equal(t, "socks5://127.0.0.1:1080", fc.NextProxy.URL)
	require.True(t, fc.NextProxy.EnableUDP)
	require.True(t, fc.PprofEnabled)
}

// TestServerConfigLegacyKeys 固定旧键 domain/listen 的映射：domain 映射到 host，
// listen 拆成 bind+port（含 IPv6 与不带主机名的通配写法）。
func TestServerConfigLegacyKeys(t *testing.T) {
	cases := []struct {
		name string
		body string
		host string
		bind string
		port int
		addr string
	}{
		{
			name: "通配监听",
			body: `{"domain":"example.com","listen":":8443"}`,
			host: "example.com",
			port: 8443,
			addr: ":8443",
		},
		{
			name: "指定 IPv4 网卡",
			body: `{"domain":"example.com","listen":"127.0.0.1:8443"}`,
			host: "example.com",
			bind: "127.0.0.1",
			port: 8443,
			addr: "127.0.0.1:8443",
		},
		{
			name: "指定 IPv6 网卡",
			body: `{"domain":"example.com","listen":"[::1]:8443"}`,
			host: "example.com",
			bind: "::1",
			port: 8443,
			addr: "[::1]:8443",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sc ServerConfig
			require.NoError(t, json.Unmarshal([]byte(tc.body), &sc))
			require.Equal(t, tc.host, sc.Host)
			require.Equal(t, tc.bind, sc.Bind)
			require.Equal(t, tc.port, sc.Port)
			require.Equal(t, tc.addr, sc.ListenAddr())
		})
	}
}

// TestServerConfigRejectsAmbiguousKeys 固定新旧键不能同时出现：否则无法判断
// 哪一个才是用户意图，静默选择任意一个都会让配置与运行行为不一致。
func TestServerConfigRejectsAmbiguousKeys(t *testing.T) {
	for _, body := range []string{
		`{"host":"example.com","domain":"other.example.com"}`,
		`{"host":"example.com","port":443,"listen":":443"}`,
		`{"host":"example.com","bind":"127.0.0.1","listen":":443"}`,
		`{"host":"example.com","listen":":443"}`,
		`{"domain":"example.com","bind":"127.0.0.1"}`,
	} {
		var sc ServerConfig
		err := json.Unmarshal([]byte(body), &sc)
		require.Error(t, err, "body %s", body)
	}
}

// TestServerConfigRejectsInvalidListen 固定旧 listen 必须是 host:port 形态：
// 缺端口时在加载阶段就报错，而不是留到运行期。
func TestServerConfigRejectsInvalidListen(t *testing.T) {
	for _, body := range []string{
		`{"listen":"443"}`,
		`{"listen":"127.0.0.1"}`,
	} {
		var sc ServerConfig
		err := json.Unmarshal([]byte(body), &sc)
		require.Error(t, err, "body %s", body)
	}
}

// TestServerConfigListenAddr 固定监听地址的唯一格式化入口：空 bind 表示所有
// 网卡，IPv6 会自动加方括号。
func TestServerConfigListenAddr(t *testing.T) {
	cases := []struct {
		name string
		bind string
		port int
		want string
	}{
		{"通配", "", 443, ":443"},
		{"未配置端口回退默认值", "", 0, ":443"},
		{"IPv4", "127.0.0.1", 8443, "127.0.0.1:8443"},
		{"IPv6", "::1", 8443, "[::1]:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := ServerConfig{Bind: tc.bind, Port: tc.port}
			require.Equal(t, tc.want, sc.ListenAddr())
		})
	}
}

// TestLoadConfigPortDefaultAndValidation 固定 port 的默认值与边界：0 取默认 443，
// 越界值直接报配置错误（不钳制）。
func TestLoadConfigPortDefaultAndValidation(t *testing.T) {
	fc, err := LoadConfig(writeConfig(t, `{"server":{"host":"example.com"}}`))
	require.NoError(t, err)
	require.Equal(t, sharedconfig.DefaultServerPort, fc.Server.Port)
	require.Equal(t, ":443", fc.Server.ListenAddr())

	fc, err = LoadConfig(writeConfig(t, `{"server":{"host":"example.com","port":8443}}`))
	require.NoError(t, err)
	require.Equal(t, 8443, fc.Server.Port)

	for _, port := range []int{-1, 65536} {
		_, err := LoadConfig(writeConfig(t, fmt.Sprintf(`{"server":{"host":"example.com","port":%d}}`, port)))
		require.ErrorContains(t, err, "server.port", "port %d", port)
	}
}

// TestValidateTreatsZeroPortAsDefault 固定 FileConfig.Validate 的直接调用语义：
// 它不要求调用方先执行 applyDefaults，Port==0 按 ListenAddr 的默认端口校验；
// 非零端口与 bind 仍必须在这里被拒绝（server.New 依赖这一点）。
func TestValidateTreatsZeroPortAsDefault(t *testing.T) {
	fc := &FileConfig{Server: ServerConfig{Host: "example.com"}}
	require.NoError(t, fc.Validate())

	fc.Server.Port = 70000
	require.ErrorContains(t, fc.Validate(), "server.port")

	fc.Server.Port = 0
	fc.Server.Bind = "127.0.0.1:443"
	require.ErrorContains(t, fc.Validate(), "server.bind")
}

// TestLoadConfigLegacyListen 固定旧配置能完整加载并保留绑定地址。
func TestLoadConfigLegacyListen(t *testing.T) {
	fc, err := LoadConfig(writeConfig(t, `{"server":{"listen":"127.0.0.1:8443","domain":"example.com","password":"p"}}`))
	require.NoError(t, err)
	require.Equal(t, "example.com", fc.Server.Host)
	require.Equal(t, 8443, fc.Server.Port)
	require.Equal(t, "127.0.0.1", fc.Server.Bind)
	require.Equal(t, "127.0.0.1:8443", fc.Server.ListenAddr())
}

// TestLoadConfigRejectsInvalidBind 固定 bind 只接受主机名或 IP 字面量：带端口或
// 方括号的写法在加载阶段就报错。
func TestLoadConfigRejectsInvalidBind(t *testing.T) {
	for _, bind := range []string{"127.0.0.1:8443", "[::1]", "host:port"} {
		body := fmt.Sprintf(`{"server":{"host":"example.com","bind":%q}}`, bind)
		_, err := LoadConfig(writeConfig(t, body))
		require.ErrorContains(t, err, "server.bind", "bind %q", bind)
	}
}

func TestResolveFilePaths(t *testing.T) {
	relCert := "server.crt"
	relNextProxy := "next_proxy.txt"
	abs, err := filepath.Abs("server.key")
	if err != nil {
		t.Fatal(err)
	}

	fc := &FileConfig{
		Server: ServerConfig{
			CertPath: relCert,
			KeyPath:  abs,
		},
		NextProxy: NextProxyConfig{
			NextProxyFile: relNextProxy,
		},
		Log: LogConfig{
			FilePath: filepath.Join("logs", "easyss.log"),
		},
	}

	fc.ResolveFilePaths()

	if want := filepath.Join(util.CurrentDir(), relCert); fc.Server.CertPath != want {
		t.Errorf("CertPath = %q, want %q", fc.Server.CertPath, want)
	}
	if fc.Server.KeyPath != abs {
		t.Errorf("KeyPath = %q, want %q (absolute unchanged)", fc.Server.KeyPath, abs)
	}
	if want := filepath.Join(util.CurrentDir(), relNextProxy); fc.NextProxy.NextProxyFile != want {
		t.Errorf("NextProxyFile = %q, want %q", fc.NextProxy.NextProxyFile, want)
	}
	// 日志路径没有"当前工作目录已存在则保留"的兼容语义，一律绝对化。
	if want := filepath.Join(util.CurrentDir(), "logs", "easyss.log"); fc.Log.FilePath != want {
		t.Errorf("Log.FilePath = %q, want %q", fc.Log.FilePath, want)
	}
}

func TestResolveFilePathsEmpty(t *testing.T) {
	fc := &FileConfig{}
	fc.ResolveFilePaths()

	if fc.Server.CertPath != "" || fc.Server.KeyPath != "" || fc.NextProxy.NextProxyFile != "" || fc.Log.FilePath != "" {
		t.Errorf("empty paths should stay empty, got %+v", fc)
	}
}

// TestResolveFilePathsCarriesIntoResolvedPaths 固定 ResolveFilePaths 就地
// 改写字段的行为：在移除 EffectiveServerConfig 合并之后，已不存在需要保持
// 同步的第二份副本。
func TestResolveFilePathsResolvedInPlace(t *testing.T) {
	fc := &FileConfig{
		Server: ServerConfig{
			CertPath: "server.crt",
			KeyPath:  "server.key",
		},
		NextProxy: NextProxyConfig{
			NextProxyFile: "next_proxy.txt",
		},
		Timeout: 30,
	}

	fc.ResolveFilePaths()

	if want := filepath.Join(util.CurrentDir(), "server.crt"); fc.Server.CertPath != want {
		t.Errorf("CertPath = %q, want %q", fc.Server.CertPath, want)
	}
	if want := filepath.Join(util.CurrentDir(), "next_proxy.txt"); fc.NextProxy.NextProxyFile != want {
		t.Errorf("NextProxyFile = %q, want %q", fc.NextProxy.NextProxyFile, want)
	}
	if fc.Timeout != 30 {
		t.Errorf("Timeout = %d, want 30", fc.Timeout)
	}
}
