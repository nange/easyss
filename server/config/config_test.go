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
// 归一化（timeout 写回、log.level 取常量默认值）且相对文件路径已解析，因此
// cmd/easyss-server 不再需要自己排列这些步骤。
func TestLoadConfigAppliesDefaults(t *testing.T) {
	fc, err := LoadConfig(writeConfig(t, `{"server":{"cert_path":"server.crt"},"log":{"file_path":"logs/easyss.log"}}`))
	require.NoError(t, err)

	require.Equal(t, sharedconfig.DefaultTimeout, fc.Timeout)
	require.Equal(t, sharedconfig.DefaultLogLevel, fc.Log.Level)
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
		fc, err := LoadConfig(writeConfig(t, fmt.Sprintf(`{"timeout":%d}`, tc.in)))
		require.NoError(t, err)
		if fc.Timeout != tc.want {
			t.Errorf("timeout %d -> %d, want %d", tc.in, fc.Timeout, tc.want)
		}
	}
}

// TestLoadConfigRejectsUnsupportedVersion 固定版本校验的位置与宽容度：其他主版本
// 的配置被拒绝，而字段缺失（0）与当前版本都被接受。
func TestLoadConfigRejectsUnsupportedVersion(t *testing.T) {
	_, err := LoadConfig(writeConfig(t, `{"version":2}`))
	require.ErrorContains(t, err, "unsupported config version")

	for _, body := range []string{`{}`, fmt.Sprintf(`{"version":%d}`, SupportedConfigVersion)} {
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

// TestApplyDefaultsIsIdempotent 守护"已归一化的配置再次归一化不变"，也固定它
// 只覆盖没有其他 owner 的字段：显式配置的日志级别必须原样保留。
func TestApplyDefaultsIsIdempotent(t *testing.T) {
	fc := FileConfig{Timeout: sharedconfig.MaxTimeout + 1, Log: LogConfig{Level: "debug"}}
	applyDefaults(&fc)

	require.Equal(t, sharedconfig.MaxTimeout, fc.Timeout)
	require.Equal(t, "debug", fc.Log.Level)

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
	require.Equal(t, []string{sharedconfig.DefaultProtocol}, fc.Transport.Protocols)
	require.Equal(t, SupportedConfigVersion, fc.ConfigVersion)

	// 示例必须能完整序列化出全部字段（新增字段时不会静默漏在示例之外），
	// 且空列表呈现为 []（与 README 的"默认值 []"一致），不是 null。
	data, err := json.Marshal(fc)
	require.NoError(t, err)
	require.Contains(t, string(data), `"cdn_domains":[]`)
	require.Contains(t, string(data), `"mesh_peers":[]`)
	// 已移除的 server.vpn.derp_addr 不该再出现在示例里：DERP 的对外地址由
	// domain 与 listen 推导，示例里没有任何可写的字段。
	require.NotContains(t, string(data), `"derp_addr"`)
	for _, key := range []string{
		`"server"`, `"fallback"`, `"shaper"`, `"transport"`,
		`"next_proxy"`, `"log"`, `"pprof_enabled"`, `"timeout"`,
		`"vpn"`, `"mesh_key"`, `"mesh_peers"`,
	} {
		require.Contains(t, string(data), key)
	}
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
			"listen": ":443",
			"domain": "example.com",
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
	require.Equal(t, ":443", fc.Server.Listen)
	require.Equal(t, "secret", fc.Server.Password)
	require.Equal(t, []string{"aes-256-gcm"}, fc.Server.AllowedMethods)
	require.Equal(t, "fallback.html", fc.Fallback.Target)
	require.Equal(t, 30, fc.Timeout)
	require.Equal(t, "socks5://127.0.0.1:1080", fc.NextProxy.URL)
	require.True(t, fc.NextProxy.EnableUDP)
	require.True(t, fc.PprofEnabled)
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
