package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
)

// testDefaultConfig 构造一份已归一化的默认配置。生产加载路径不经过它：
// 完整模式走 LoadConfig/ParseConfigJSON，简化模式走 BuildSimpleConfig。
func testDefaultConfig() *ClientConfig {
	cfg := &ClientConfig{
		ConfigVersion: 3,
		Local:         LocalConfig{SocksPort: config.DefaultSocksPort},
	}
	applyDefaults(cfg)
	return cfg
}

func TestApplyDefaultsLocalPorts(t *testing.T) {
	cfg := testDefaultConfig()
	if cfg.ConfigVersion != 3 {
		t.Errorf("ConfigVersion = %d, want 3", cfg.ConfigVersion)
	}
	if cfg.Local.SocksPort != 4080 {
		t.Errorf("SocksPort = %d, want 4080", cfg.Local.SocksPort)
	}
	if cfg.Local.HTTPPort != 5080 {
		t.Errorf("HTTPPort = %d, want 5080", cfg.Local.HTTPPort)
	}
	if cfg.Timeout != config.DefaultTimeout {
		t.Errorf("Timeout = %d, want %d", cfg.Timeout, config.DefaultTimeout)
	}
	if cfg.Transport.Protocol != "h2" {
		t.Errorf("Protocol = %q, want h2", cfg.Transport.Protocol)
	}
	if cfg.Routing.ProxyRule != "auto" {
		t.Errorf("ProxyRule = %q, want auto", cfg.Routing.ProxyRule)
	}
	if cfg.Routing.IPV6Rule != "auto" {
		t.Errorf("IPV6Rule = %q, want auto", cfg.Routing.IPV6Rule)
	}
}

func TestClone(t *testing.T) {
	cfg := testDefaultConfig()
	cfg.Servers = []*ServerProfile{
		{Host: "example.com", Port: 443, Password: "secret", Default: true},
	}

	clone := cfg.Clone()
	if clone == nil {
		t.Fatal("Clone returned nil")
	}
	if clone == cfg {
		t.Error("Clone returned same pointer")
	}
	if clone.ConfigVersion != cfg.ConfigVersion {
		t.Error("ConfigVersion mismatch")
	}
	if clone.Servers[0].Host != cfg.Servers[0].Host {
		t.Error("Server host mismatch")
	}

	// 验证深拷贝：修改 clone 不影响原对象
	clone.Servers[0].Port = 8443
	if cfg.Servers[0].Port == 8443 {
		t.Error("Clone did not deep copy servers")
	}

	// json:"-" 字段不在线格式里，但属于快照的一部分：JSON 往返会把它清零。
	cfg.Shaper.IdleTimeout = 500
	cfg.Local.TunConfig = json.RawMessage(`{"device":"utun9"}`)
	clone = cfg.Clone()
	if clone.Shaper.IdleTimeout != 500 {
		t.Errorf("Clone lost json:\"-\" field: IdleTimeout = %d, want 500", clone.Shaper.IdleTimeout)
	}
	clone.Local.TunConfig[0] = 'x'
	if cfg.Local.TunConfig[0] == 'x' {
		t.Error("Clone shares the Local.TunConfig backing array")
	}
}

// TestCloneSharesNoMutableState 按类型遍历而不是按字段清单，因此新增 slice/map/指针字段
// 却忘了在 Clone 里复制时，这里必然失败。
func TestCloneSharesNoMutableState(t *testing.T) {
	src := testDefaultConfig()
	src.Servers = []*ServerProfile{
		{Host: "example.com", Port: 443, Password: "secret", Default: true},
		{Host: "192.0.2.1", Port: 443},
	}
	src.Local.TunConfig = json.RawMessage(`{"device":"utun9"}`)
	src.Shaper.IdleTimeout = 500

	clone := src.Clone()
	assertNoSharedRefs(t, "ClientConfig", reflect.ValueOf(*src), reflect.ValueOf(*clone))
}

// assertNoSharedRefs 报告 clone 与 src 之间仍然共享的可变引用。字符串与函数值按值语义
// 共享，不在此列。
func assertNoSharedRefs(t *testing.T, path string, src, clone reflect.Value) {
	t.Helper()
	if src.Type() != clone.Type() {
		t.Fatalf("%s: type mismatch: %s vs %s", path, src.Type(), clone.Type())
	}
	switch src.Kind() {
	case reflect.Struct:
		for i := range src.NumField() {
			assertNoSharedRefs(t, path+"."+src.Type().Field(i).Name, src.Field(i), clone.Field(i))
		}
	case reflect.Array:
		for i := range src.Len() {
			assertNoSharedRefs(t, fmt.Sprintf("%s[%d]", path, i), src.Index(i), clone.Index(i))
		}
	case reflect.Slice:
		if src.IsNil() != clone.IsNil() {
			t.Errorf("%s: Clone changed nil-ness", path)
			return
		}
		if src.Len() > 0 && src.Pointer() == clone.Pointer() {
			t.Errorf("%s: Clone shares the backing array", path)
			return
		}
		for i := range src.Len() {
			assertNoSharedRefs(t, fmt.Sprintf("%s[%d]", path, i), src.Index(i), clone.Index(i))
		}
	case reflect.Pointer, reflect.Map:
		if src.IsNil() != clone.IsNil() {
			t.Errorf("%s: Clone changed nil-ness", path)
			return
		}
		if src.IsNil() {
			return
		}
		if src.Pointer() == clone.Pointer() {
			t.Errorf("%s: Clone shares the %s", path, src.Kind())
			return
		}
		if src.Kind() == reflect.Pointer {
			assertNoSharedRefs(t, path, src.Elem(), clone.Elem())
		}
	case reflect.Interface:
		if src.IsNil() != clone.IsNil() {
			t.Errorf("%s: Clone changed nil-ness", path)
			return
		}
		if !src.IsNil() {
			assertNoSharedRefs(t, path, src.Elem(), clone.Elem())
		}
	}
}

func TestDefaultServer(t *testing.T) {
	tests := []struct {
		name    string
		servers []*ServerProfile
		want    string // 期望返回的 Host，空表示 nil
	}{
		{
			name:    "空服务器列表",
			servers: nil,
			want:    "",
		},
		{
			name: "有默认标记的服务器",
			servers: []*ServerProfile{
				{Host: "s1.example.com", Default: false},
				{Host: "s2.example.com", Default: true},
				{Host: "s3.example.com", Default: false},
			},
			want: "s2.example.com",
		},
		{
			name: "无默认标记时返回第一个",
			servers: []*ServerProfile{
				{Host: "s1.example.com", Default: false},
				{Host: "s2.example.com", Default: false},
			},
			want: "s1.example.com",
		},
		{
			name: "多个默认标记时返回第一个",
			servers: []*ServerProfile{
				{Host: "s1.example.com", Default: true},
				{Host: "s2.example.com", Default: true},
			},
			want: "s1.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ClientConfig{Servers: tt.servers}
			srv := cfg.DefaultServer()
			if tt.want == "" {
				if srv != nil {
					t.Errorf("got %v, want nil", srv)
				}
			} else {
				if srv == nil {
					t.Fatal("got nil, want non-nil")
				}
				if srv.Host != tt.want {
					t.Errorf("Host = %q, want %q", srv.Host, tt.want)
				}
			}
		})
	}
}

func TestServerURL(t *testing.T) {
	t.Run("有默认服务器", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "example.com", Port: 443, Default: true},
			},
		}
		if url := cfg.ServerURL(); url != "https://example.com:443" {
			t.Errorf("ServerURL = %q, want https://example.com:443", url)
		}
	})

	t.Run("IPv6 字面量自动加方括号", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "2001:db8::1", Port: 443, Default: true},
			},
		}
		if url := cfg.ServerURL(); url != "https://[2001:db8::1]:443" {
			t.Errorf("ServerURL = %q, want bracketed IPv6", url)
		}
	})

	t.Run("无服务器", func(t *testing.T) {
		cfg := &ClientConfig{}
		if url := cfg.ServerURL(); url != "" {
			t.Errorf("ServerURL = %q, want empty", url)
		}
	})
}

func TestTimeoutDuration(t *testing.T) {
	t.Run("正值", func(t *testing.T) {
		cfg := &ClientConfig{Timeout: 60}
		if d := cfg.TimeoutDuration(); d.Seconds() != 60 {
			t.Errorf("TimeoutDuration = %v, want 60s", d)
		}
	})

	t.Run("零值使用默认", func(t *testing.T) {
		cfg := &ClientConfig{Timeout: 0}
		if d := cfg.TimeoutDuration(); d.Seconds() != float64(config.DefaultTimeout) {
			t.Errorf("TimeoutDuration = %v, want %ds", d, config.DefaultTimeout)
		}
	})

	t.Run("负值使用默认", func(t *testing.T) {
		cfg := &ClientConfig{Timeout: -1}
		if d := cfg.TimeoutDuration(); d.Seconds() != float64(config.DefaultTimeout) {
			t.Errorf("TimeoutDuration = %v, want %ds", d, config.DefaultTimeout)
		}
	})

	t.Run("低于下限钳制", func(t *testing.T) {
		cfg := &ClientConfig{Timeout: 1}
		if d := cfg.TimeoutDuration(); d.Seconds() != float64(config.MinTimeout) {
			t.Errorf("TimeoutDuration = %v, want %ds", d, config.MinTimeout)
		}
	})

	t.Run("高于上限钳制", func(t *testing.T) {
		cfg := &ClientConfig{Timeout: 3600}
		if d := cfg.TimeoutDuration(); d.Seconds() != float64(config.MaxTimeout) {
			t.Errorf("TimeoutDuration = %v, want %ds", d, config.MaxTimeout)
		}
	})
}

// TestConnLifetimeDuration 固定连接轮换生命周期的派生：它不再可配置，
// 完全跟随基础超时（12 倍 timeout）。
func TestConnLifetimeDuration(t *testing.T) {
	t.Run("默认基础超时", func(t *testing.T) {
		cfg := &ClientConfig{Timeout: 30}
		if d := cfg.ConnLifetimeDuration(); d != 6*time.Minute {
			t.Errorf("ConnLifetimeDuration = %v, want 6m", d)
		}
	})

	t.Run("随 timeout 缩放", func(t *testing.T) {
		cfg := &ClientConfig{Timeout: 60}
		if d := cfg.ConnLifetimeDuration(); d != 12*time.Minute {
			t.Errorf("ConnLifetimeDuration = %v, want 12m", d)
		}
	})

	t.Run("timeout 非法时用默认基础超时", func(t *testing.T) {
		want := config.ConnLifetime(time.Duration(config.DefaultTimeout) * time.Second)
		for _, timeout := range []int{0, -1} {
			cfg := &ClientConfig{Timeout: timeout}
			if d := cfg.ConnLifetimeDuration(); d != want {
				t.Errorf("ConnLifetimeDuration(timeout=%d) = %v, want %v", timeout, d, want)
			}
		}
	})
}

func TestSetDefaultServerIndex(t *testing.T) {
	cfg := &ClientConfig{
		Servers: []*ServerProfile{
			{Host: "s1.example.com"},
			{Host: "s2.example.com"},
			{Host: "s3.example.com"},
		},
	}

	cfg.SetDefaultServerIndex(1)
	if !cfg.Servers[1].Default {
		t.Error("server 1 should be default")
	}
	if cfg.Servers[0].Default || cfg.Servers[2].Default {
		t.Error("only server 1 should be default")
	}

	// 切换到另一个索引
	cfg.SetDefaultServerIndex(2)
	if !cfg.Servers[2].Default {
		t.Error("server 2 should be default")
	}
	if cfg.Servers[1].Default {
		t.Error("server 1 should no longer be default")
	}
}

func TestServerListAddrs(t *testing.T) {
	t.Run("多服务器", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "s1.example.com", Port: 443},
				{Host: "s2.example.com", Port: 8443},
			},
		}
		addrs := cfg.ServerListAddrs()
		if len(addrs) != 2 {
			t.Fatalf("len = %d, want 2", len(addrs))
		}
		if addrs[0] != "s1.example.com:443" {
			t.Errorf("addrs[0] = %q", addrs[0])
		}
		if addrs[1] != "s2.example.com:8443" {
			t.Errorf("addrs[1] = %q", addrs[1])
		}
	})

	t.Run("IPv6 字面量自动加方括号", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{{Host: "2001:db8::1", Port: 443}},
		}
		addrs := cfg.ServerListAddrs()
		if len(addrs) != 1 || addrs[0] != "[2001:db8::1]:443" {
			t.Errorf("addrs = %v", addrs)
		}
	})

	t.Run("空列表", func(t *testing.T) {
		cfg := &ClientConfig{}
		addrs := cfg.ServerListAddrs()
		if len(addrs) != 0 {
			t.Errorf("len = %d, want 0", len(addrs))
		}
	})
}

func TestDefaultServerAddr(t *testing.T) {
	t.Run("有默认服务器", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "example.com", Port: 443, Default: true},
			},
		}
		if addr := cfg.DefaultServerAddr(); addr != "example.com:443" {
			t.Errorf("DefaultServerAddr = %q", addr)
		}
	})

	t.Run("IPv6 字面量自动加方括号", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "2001:db8::1", Port: 443, Default: true},
			},
		}
		if addr := cfg.DefaultServerAddr(); addr != "[2001:db8::1]:443" {
			t.Errorf("DefaultServerAddr = %q, want bracketed IPv6", addr)
		}
	})

	t.Run("无服务器", func(t *testing.T) {
		cfg := &ClientConfig{}
		if addr := cfg.DefaultServerAddr(); addr != "" {
			t.Errorf("DefaultServerAddr = %q, want empty", addr)
		}
	})
}

func TestDefaultServerIndex(t *testing.T) {
	t.Run("有默认标记", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "s1.example.com"},
				{Host: "s2.example.com", Default: true},
			},
		}
		if idx := cfg.DefaultServerIndex(); idx != 1 {
			t.Errorf("DefaultServerIndex = %d, want 1", idx)
		}
	})

	t.Run("无默认标记返回0", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "s1.example.com"},
				{Host: "s2.example.com"},
			},
		}
		if idx := cfg.DefaultServerIndex(); idx != 0 {
			t.Errorf("DefaultServerIndex = %d, want 0", idx)
		}
	})

	t.Run("空列表返回0", func(t *testing.T) {
		cfg := &ClientConfig{}
		if idx := cfg.DefaultServerIndex(); idx != 0 {
			t.Errorf("DefaultServerIndex = %d, want 0", idx)
		}
	})
}

func TestBuildSimpleConfig(t *testing.T) {
	t.Run("完整简化配置构建", func(t *testing.T) {
		v2 := config.SimpleConfig{
			Server:           "example.com",
			ServerPort:       443,
			Password:         "secret",
			Method:           "aes-256-gcm",
			SN:               "sni.example.com",
			LocalPort:        1080,
			HTTPPort:         2080,
			BindAll:          true,
			DisableSysProxy:  true,
			EnableForwardDNS: true,
			ProxyRule:        "proxy",
			IPV6Rule:         "enable",
			DirectFile:       "/etc/direct.txt",
			ProxyFile:        "/etc/proxy.txt",
			Timeout:          60,
			LogLevel:         "debug",
			LogFilePath:      "/var/log/easyss.log",
			OutboundProto:    "h2",
		}

		v3, err := BuildSimpleConfig(&v2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if v3.ConfigVersion != 3 {
			t.Errorf("ConfigVersion = %d", v3.ConfigVersion)
		}
		if v3.Servers[0].Host != "example.com" {
			t.Errorf("Host = %q", v3.Servers[0].Host)
		}
		if v3.Servers[0].Port != 443 {
			t.Errorf("Port = %d", v3.Servers[0].Port)
		}
		if v3.Servers[0].SNI != "sni.example.com" {
			t.Errorf("SNI = %q", v3.Servers[0].SNI)
		}
		if v3.Local.SocksPort != 1080 {
			t.Errorf("SocksPort = %d", v3.Local.SocksPort)
		}
		if !v3.Local.BindAll {
			t.Error("BindAll should be true")
		}
		if v3.Transport.Protocol != "h2" {
			t.Errorf("Protocol = %q", v3.Transport.Protocol)
		}
		if v3.Routing.ProxyRule != "proxy" {
			t.Errorf("ProxyRule = %q", v3.Routing.ProxyRule)
		}
		if v3.Routing.IPV6Rule != "enable" {
			t.Errorf("IPV6Rule = %q", v3.Routing.IPV6Rule)
		}
		if v3.Timeout != 60 {
			t.Errorf("Timeout = %d", v3.Timeout)
		}
		if v3.Log.Level != "debug" {
			t.Errorf("LogLevel = %q", v3.Log.Level)
		}
	})

	t.Run("简化配置默认值填充", func(t *testing.T) {
		v2 := config.SimpleConfig{
			Server:   "example.com",
			Password: "secret",
		}

		v3, err := BuildSimpleConfig(&v2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if v3.Servers[0].Port != 443 {
			t.Errorf("Port = %d, want 443", v3.Servers[0].Port)
		}
		if v3.Servers[0].Method != "aes-256-gcm" {
			t.Errorf("Method = %q, want aes-256-gcm", v3.Servers[0].Method)
		}
		if v3.Timeout != 30 {
			t.Errorf("Timeout = %d, want 30", v3.Timeout)
		}
		if v3.Log.Level != "info" {
			t.Errorf("LogLevel = %q, want info", v3.Log.Level)
		}
		if v3.Routing.ProxyRule != "auto" {
			t.Errorf("ProxyRule = %q, want auto", v3.Routing.ProxyRule)
		}
	})

	t.Run("简化配置 HTTPPort 自动计算", func(t *testing.T) {
		v2 := config.SimpleConfig{
			Server:    "example.com",
			Password:  "secret",
			LocalPort: 1080,
			// HTTPPort 未设置
		}

		v3, err := BuildSimpleConfig(&v2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if v3.Local.HTTPPort != 2080 {
			t.Errorf("HTTPPort = %d, want 2080 (SocksPort + 1000)", v3.Local.HTTPPort)
		}
	})

	t.Run("简化配置 OutboundProto 校验", func(t *testing.T) {
		v2 := config.SimpleConfig{
			Server:        "example.com",
			Password:      "secret",
			OutboundProto: "invalid",
		}

		_, err := BuildSimpleConfig(&v2)
		if err == nil {
			t.Error("expected error for invalid outbound_proto")
		}
	})

	t.Run("简化配置 tun_config 校验", func(t *testing.T) {
		valid := config.SimpleConfig{Server: "example.com", Password: "secret", TunConfig: `{"device":"utun9"}`}
		v3, err := BuildSimpleConfig(&valid)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(v3.Local.TunConfig) != `{"device":"utun9"}` {
			t.Errorf("TunConfig = %q", v3.Local.TunConfig)
		}

		invalid := config.SimpleConfig{Server: "example.com", Password: "secret", TunConfig: `{invalid`}
		if _, err := BuildSimpleConfig(&invalid); err == nil {
			t.Error("expected error for malformed tun_config")
		}
	})
}

// TestSimpleOverridesUseHost 固定简化模式覆盖写入的是 Host（而不是旧的
// Address 字段），与 BuildSimpleConfig 的构建路径保持一致。
func TestSimpleOverridesUseHost(t *testing.T) {
	cfg := &ClientConfig{
		Servers: []*ServerProfile{{Host: "old.example", Port: 443}},
	}
	if err := ApplySimpleOverrides(cfg, &config.SimpleConfig{Server: "new.example", ServerPort: 8443}); err != nil {
		t.Fatal(err)
	}
	if cfg.Servers[0].Host != "new.example" {
		t.Errorf("Host = %q, want new.example", cfg.Servers[0].Host)
	}
	if cfg.Servers[0].Port != 8443 {
		t.Errorf("Port = %d, want 8443", cfg.Servers[0].Port)
	}
}

// TestApplySimpleOverridesRejectsHostWithPort 固定命令行覆盖也要过与文件加载
// 相同的 host 校验：-s 里带端口不能留到拨号时才以 "too many colons" 暴露。
func TestApplySimpleOverridesRejectsHostWithPort(t *testing.T) {
	cfg := &ClientConfig{Servers: []*ServerProfile{{Host: "old.example", Port: 443}}}
	err := ApplySimpleOverrides(cfg, &config.SimpleConfig{Server: "new.example:443"})
	if err == nil {
		t.Fatal("expected error for host with port")
	}
	if !strings.Contains(err.Error(), "must not include a port") {
		t.Errorf("error = %v, want port hint", err)
	}
}

// TestApplySimpleOverridesRejectsInvalidTunConfig 与 tun_config 的加载路径同一条判据：
// 非法 JSON 会在消费点静默失效，必须在覆盖阶段就报错。
func TestApplySimpleOverridesRejectsInvalidTunConfig(t *testing.T) {
	cfg := &ClientConfig{Servers: []*ServerProfile{{Host: "old.example", Port: 443}}}
	err := ApplySimpleOverrides(cfg, &config.SimpleConfig{TunConfig: `{invalid`})
	if err == nil {
		t.Fatal("expected error for malformed tun_config")
	}
	if !strings.Contains(err.Error(), "tun_config") {
		t.Errorf("error = %v, want tun_config hint", err)
	}
}

// TestValidateServers 固定 host 的基本契约：必填、允许 IPv6 字面量，但不得把
// 端口写进 host（否则 ServerURL 会拼出 https://host:port:port）。
func TestValidateServers(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"域名", "example.com", false},
		{"IPv4", "1.2.3.4", false},
		{"IPv6 字面量", "2001:db8::1", false},
		{"域名带端口", "example.com:443", true},
		{"IPv4 带端口", "1.2.3.4:443", true},
		{"IPv6 带端口", "[2001:db8::1]:443", true},
		{"空 host", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &ClientConfig{Servers: []*ServerProfile{{Host: tc.host}}}
			err := cfg.validateServers()
			if tc.wantErr && err == nil {
				t.Errorf("expected error for host %q", tc.host)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("host %q: unexpected error: %v", tc.host, err)
			}
		})
	}

	if err := (&ClientConfig{Servers: []*ServerProfile{nil}}).validateServers(); err == nil {
		t.Error("expected error for nil server entry")
	}
}

// TestBuildSimpleConfigRejectsHostWithPort 固定简化模式也不会把 host:port 当成
// 合法主机名，避免迁移时在运行期才拼出错误地址。
func TestBuildSimpleConfigRejectsHostWithPort(t *testing.T) {
	if _, err := BuildSimpleConfig(&config.SimpleConfig{Server: "example.com:443", Password: "secret"}); err == nil {
		t.Error("expected error for host with port")
	}
}

func TestOutboundProtoToProtocol(t *testing.T) {
	tests := []struct {
		proto   string
		want    string
		wantErr bool
	}{
		{"", "h2", false},
		{"native", "h2", false},
		{"h2", "h2", false},
		{"invalid", "", true},
		{"H2", "", true}, // 大小写敏感
	}

	for _, tt := range tests {
		t.Run(tt.proto, func(t *testing.T) {
			got, err := OutboundProtoToProtocol(tt.proto)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("got %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("加载 v3 配置", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		v3JSON := `{
			"version": 3,
			"servers": [{"host": "example.com", "port": 443, "password": "secret", "default": true}],
			"local": {"socks_port": 1080},
			"routing": {"proxy_rule": "proxy"},
			"transport": {},
			"shaper": {},
			"log": {"level": "debug"},
			"timeout": 60
		}`
		if err := os.WriteFile(path, []byte(v3JSON), 0644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Servers[0].Host != "example.com" {
			t.Errorf("Host = %q", cfg.Servers[0].Host)
		}
		if cfg.Routing.ProxyRule != "proxy" {
			t.Errorf("ProxyRule = %q", cfg.Routing.ProxyRule)
		}
		if cfg.Log.Level != "debug" {
			t.Errorf("LogLevel = %q", cfg.Log.Level)
		}
	})

	t.Run("旧 address 兼容", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		body := `{
			"version": 3,
			"servers": [{"address": "example.com", "port": 8443, "password": "secret"}]
		}`
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Servers[0].Host != "example.com" {
			t.Errorf("Host = %q", cfg.Servers[0].Host)
		}
		if cfg.Servers[0].Port != 8443 {
			t.Errorf("Port = %d", cfg.Servers[0].Port)
		}
	})

	t.Run("host 与 address 冲突", func(t *testing.T) {
		_, err := ParseConfigJSON(`{"servers":[{"host":"a.example","address":"b.example"}]}`)
		if err == nil {
			t.Error("expected error for host+address")
		}
	})

	t.Run("host 带端口启动失败", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		body := `{"version":3,"servers":[{"host":"example.com:443","port":443,"password":"secret"}]}`
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig(path)
		if err == nil {
			t.Error("expected error for host with port")
		}
	})

	t.Run("host 为空启动失败", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		body := `{"version":3,"servers":[{"port":443,"password":"secret"}]}`
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig(path)
		if err == nil {
			t.Error("expected error for empty host")
		}
	})

	t.Run("序列化只输出 host", func(t *testing.T) {
		cfg := &ClientConfig{
			ConfigVersion: 3,
			Servers:       []*ServerProfile{{Host: "example.com", Port: 443}},
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var raw struct {
			Servers []map[string]json.RawMessage `json:"servers"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw.Servers[0]["host"]; !ok {
			t.Errorf("serialized config missing host: %s", data)
		}
		if _, ok := raw.Servers[0]["address"]; ok {
			t.Errorf("serialized config must not contain address: %s", data)
		}
	})

	// http_port 的推导（socks_port + 1000）在简化模式与完整模式下必须一致：
	// 只在简化模式推导会让完整模式"少一个本地端口"。
	t.Run("http_port 由 socks_port 推导", func(t *testing.T) {
		tests := []struct {
			name      string
			localJSON string
			wantSocks int
			wantHTTP  int
		}{
			{"完整模式未配置 http_port", `{"socks_port": 1080}`, 1080, 2080},
			{"完整模式显式 http_port 优先", `{"socks_port": 1080, "http_port": 3128}`, 1080, 3128},
			{"socks_port 为 0 时不推导", `{"socks_port": 0}`, 0, 0},
			{"未配置 local 时不推导", `{}`, 0, 0},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "config.json")
				v3JSON := `{
					"version": 3,
					"servers": [{"host": "example.com", "port": 443, "password": "secret"}],
					"local": ` + tt.localJSON + `
				}`
				if err := os.WriteFile(path, []byte(v3JSON), 0644); err != nil {
					t.Fatal(err)
				}

				cfg, err := LoadConfig(path)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cfg.Local.SocksPort != tt.wantSocks {
					t.Errorf("SocksPort = %d, want %d", cfg.Local.SocksPort, tt.wantSocks)
				}
				if cfg.Local.HTTPPort != tt.wantHTTP {
					t.Errorf("HTTPPort = %d, want %d", cfg.Local.HTTPPort, tt.wantHTTP)
				}
			})
		}
	})

	t.Run("加载 v2 配置自动转换", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		v2JSON := `{
			"server": "example.com",
			"server_port": 8443,
			"password": "secret",
			"local_port": 1080,
			"proxy_rule": "auto"
		}`
		if err := os.WriteFile(path, []byte(v2JSON), 0644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.ConfigVersion != 3 {
			t.Errorf("ConfigVersion = %d, want 3", cfg.ConfigVersion)
		}
		if cfg.Servers[0].Host != "example.com" {
			t.Errorf("Host = %q", cfg.Servers[0].Host)
		}
		if cfg.Servers[0].Port != 8443 {
			t.Errorf("Port = %d", cfg.Servers[0].Port)
		}
	})

	t.Run("加载无效 JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := LoadConfig(path)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("文件不存在", func(t *testing.T) {
		_, err := LoadConfig("/nonexistent/config.json")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})
}

func TestApplyDefaults(t *testing.T) {
	t.Run("填充所有默认值", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "example.com"},
				{Host: "example2.com"},
			},
		}
		applyDefaults(cfg)

		if cfg.Timeout != config.DefaultTimeout {
			t.Errorf("Timeout = %d", cfg.Timeout)
		}
		if cfg.Transport.Protocol != "h2" {
			t.Errorf("Protocol = %q", cfg.Transport.Protocol)
		}
		if cfg.Transport.ConnCountMax != config.DefaultConnCountMax {
			t.Errorf("ConnCountMax = %d", cfg.Transport.ConnCountMax)
		}
		if cfg.Transport.StreamThreshold != config.DefaultStreamThreshold {
			t.Errorf("StreamThreshold = %d", cfg.Transport.StreamThreshold)
		}
		if cfg.Transport.ConnMaxBytes != config.DefaultConnMaxBytes {
			t.Errorf("ConnMaxBytes = %d", cfg.Transport.ConnMaxBytes)
		}
		// 此处保持 shaper 取值原样：其默认值与边界由 shaper.Config.Normalize
		// 负责（在 shaper/shaper_test.go 中固定）。
		if cfg.Shaper.BatchWindowMS != 0 {
			t.Errorf("BatchWindowMS = %d, want 0 (normalized at the shaper)", cfg.Shaper.BatchWindowMS)
		}
		if cfg.Routing.ProxyRule != "auto" {
			t.Errorf("ProxyRule = %q", cfg.Routing.ProxyRule)
		}
		if cfg.Routing.IPV6Rule != "auto" {
			t.Errorf("IPV6Rule = %q", cfg.Routing.IPV6Rule)
		}
		if cfg.Log.Level != "info" {
			t.Errorf("LogLevel = %q", cfg.Log.Level)
		}
		for _, srv := range cfg.Servers {
			if srv.Port != 443 {
				t.Errorf("Port = %d", srv.Port)
			}
			if srv.Method != "aes-256-gcm" {
				t.Errorf("Method = %q", srv.Method)
			}
		}
	})

	t.Run("Shaper 取值原样保留，归一化在 shaper 层", func(t *testing.T) {
		cfg := &ClientConfig{Shaper: shaper.Config{BatchWindowMS: 100}}
		applyDefaults(cfg)
		if cfg.Shaper.BatchWindowMS != 100 {
			t.Errorf("BatchWindowMS = %d, want 100 (untouched)", cfg.Shaper.BatchWindowMS)
		}
	})

	t.Run("已有值不被覆盖", func(t *testing.T) {
		cfg := &ClientConfig{
			Timeout: 45,
			Transport: TransportConfig{
				Protocol: "h3",
			},
			Routing: RoutingConfig{
				ProxyRule: "direct",
				IPV6Rule:  "disable",
			},
			Log: log.Config{Level: "error"},
		}
		applyDefaults(cfg)

		if cfg.Timeout != 45 {
			t.Errorf("Timeout = %d, want 45 (not overwritten)", cfg.Timeout)
		}
		if cfg.Transport.Protocol != "h3" {
			t.Errorf("Protocol = %q, want h3 (not overwritten)", cfg.Transport.Protocol)
		}
		if cfg.Routing.ProxyRule != "direct" {
			t.Errorf("ProxyRule = %q, want direct (not overwritten)", cfg.Routing.ProxyRule)
		}
		if cfg.Routing.IPV6Rule != "disable" {
			t.Errorf("IPV6Rule = %q, want disable (not overwritten)", cfg.Routing.IPV6Rule)
		}
		if cfg.Log.Level != "error" {
			t.Errorf("LogLevel = %q, want error (not overwritten)", cfg.Log.Level)
		}
	})

	t.Run("钳制退化配置到合法范围", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "example.com"},
			},
			Transport: TransportConfig{
				// conn_count_max=1 会让调度器 panic（空的 bulk 池）；
				// 过大的值则绝不能触发巨大的前置分配。
				ConnCountMax:    1,
				StreamThreshold: 1 << 30,
			},
		}
		applyDefaults(cfg)

		if cfg.Transport.ConnCountMax != config.MinConnCountMax {
			t.Errorf("ConnCountMax = %d, want clamped to %d", cfg.Transport.ConnCountMax, config.MinConnCountMax)
		}

		cfg2 := &ClientConfig{
			Servers: []*ServerProfile{
				{Host: "example.com"},
			},
			Transport: TransportConfig{
				ConnCountMax:    1 << 20,
				StreamThreshold: 1 << 20,
			},
		}
		applyDefaults(cfg2)

		if cfg2.Transport.ConnCountMax != config.MaxConnCountMax {
			t.Errorf("ConnCountMax = %d, want clamped to %d", cfg2.Transport.ConnCountMax, config.MaxConnCountMax)
		}
		if cfg2.Transport.StreamThreshold != config.MaxStreamThreshold {
			t.Errorf("StreamThreshold = %d, want clamped to %d", cfg2.Transport.StreamThreshold, config.MaxStreamThreshold)
		}
	})

	t.Run("timeout 越界钳制到合法区间", func(t *testing.T) {
		// timeout 派生出流空闲、UDP 空闲、拨号、DNS 响应与连接轮换，
		// 因此它必须落在 [MinTimeout, MaxTimeout] 内；非正值仍是"取默认值"。
		tests := []struct {
			name string
			in   int
			want int
		}{
			{"低于下限", 1, config.MinTimeout},
			{"上限内保持", 45, 45},
			{"高于上限", 3600, config.MaxTimeout},
			{"未配置", 0, config.DefaultTimeout},
			{"负值", -3, config.DefaultTimeout},
		}
		for _, tt := range tests {
			cfg := &ClientConfig{Timeout: tt.in}
			applyDefaults(cfg)
			if cfg.Timeout != tt.want {
				t.Errorf("%s: Timeout = %d, want %d", tt.name, cfg.Timeout, tt.want)
			}
		}
	})
}

// TestTimeoutClampedOnEveryEntry 覆盖 timeout 的三条入口都做同一套归一化：
// 简化模式构建（含 v2 迁移）、命令行/简单模式覆盖、以及 JSON 加载后的 applyDefaults
// （后者由 TestApplyDefaults 覆盖）。任何一条漏掉钳制，派生超时就会越界。
func TestTimeoutClampedOnEveryEntry(t *testing.T) {
	t.Run("简化模式构建", func(t *testing.T) {
		cfg, err := BuildSimpleConfig(&config.SimpleConfig{Server: "example.com", Password: "secret", Timeout: 600})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Timeout != config.MaxTimeout {
			t.Errorf("Timeout = %d, want clamped to %d", cfg.Timeout, config.MaxTimeout)
		}

		cfg, err = BuildSimpleConfig(&config.SimpleConfig{Server: "example.com", Password: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Timeout != config.DefaultTimeout {
			t.Errorf("Timeout = %d, want default %d", cfg.Timeout, config.DefaultTimeout)
		}
	})

	t.Run("简单模式覆盖", func(t *testing.T) {
		cfg := &ClientConfig{Timeout: config.DefaultTimeout}
		if err := ApplySimpleOverrides(cfg, &config.SimpleConfig{Timeout: 1}); err != nil {
			t.Fatal(err)
		}
		if cfg.Timeout != config.MinTimeout {
			t.Errorf("Timeout = %d, want clamped to %d", cfg.Timeout, config.MinTimeout)
		}

		// 未提供覆盖（0）时保持配置中的值，不会被当成"钳制到下限"。
		if err := ApplySimpleOverrides(cfg, &config.SimpleConfig{}); err != nil {
			t.Fatal(err)
		}
		if cfg.Timeout != config.MinTimeout {
			t.Errorf("Timeout = %d, want unchanged %d", cfg.Timeout, config.MinTimeout)
		}
	})
}

func TestResolveFilePaths(t *testing.T) {
	relDirect := "direct.txt"
	relCA := "ca.pem"
	abs, err := filepath.Abs("proxy.txt")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &ClientConfig{
		Routing: RoutingConfig{
			DirectFile: relDirect,
			ProxyFile:  abs,
		},
		Servers: []*ServerProfile{
			{CAPath: relCA},
			{CAPath: ""},
		},
	}

	cfg.ResolveFilePaths()

	if want := filepath.Join(util.CurrentDir(), relDirect); cfg.Routing.DirectFile != want {
		t.Errorf("DirectFile = %q, want %q", cfg.Routing.DirectFile, want)
	}
	if cfg.Routing.ProxyFile != abs {
		t.Errorf("ProxyFile = %q, want %q (absolute unchanged)", cfg.Routing.ProxyFile, abs)
	}
	if want := filepath.Join(util.CurrentDir(), relCA); cfg.Servers[0].CAPath != want {
		t.Errorf("Servers[0].CAPath = %q, want %q", cfg.Servers[0].CAPath, want)
	}
	if cfg.Servers[1].CAPath != "" {
		t.Errorf("Servers[1].CAPath = %q, want empty (unchanged)", cfg.Servers[1].CAPath)
	}
}

// TestTunMTU 固定 TUN MTU 旋钮的取值路径：越界值必须在加载时就钳制、默认值必须
// 来自 config.DefaultTunMTU（而不是散落的字面量），简单模式与命令行覆盖也必须
// 走同一个归一化入口——它同时决定 TUN 设备的真实 MTU 与 tun2socks netstack 的
// MTU，两侧一旦偏离就会静默丢包（见 client/tun.Manager.engineMTU）。
func TestTunMTU(t *testing.T) {
	t.Run("未配置取默认值", func(t *testing.T) {
		cfg := testDefaultConfig()
		if got := cfg.TunMTU(); got != config.DefaultTunMTU {
			t.Errorf("TunMTU() = %d, want %d", got, config.DefaultTunMTU)
		}
		if cfg.Local.TunMTU != config.DefaultTunMTU {
			t.Errorf("Local.TunMTU = %d, want %d (applyDefaults must write it back)",
				cfg.Local.TunMTU, config.DefaultTunMTU)
		}
	})

	t.Run("越界值在加载时钳制", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		v3JSON := `{
			"version": 3,
			"servers": [{"host": "example.com", "port": 443, "password": "secret", "default": true}],
			"local": {"socks_port": 1080, "tun_mtu": 64000}
		}`
		if err := os.WriteFile(path, []byte(v3JSON), 0644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Local.TunMTU != config.MaxTunMTU {
			t.Errorf("Local.TunMTU = %d, want %d (clamped at load time)",
				cfg.Local.TunMTU, config.MaxTunMTU)
		}
		if got := cfg.TunMTU(); got != config.MaxTunMTU {
			t.Errorf("TunMTU() = %d, want %d", got, config.MaxTunMTU)
		}
	})

	t.Run("区间内的值原样保留", func(t *testing.T) {
		cfg := &ClientConfig{Local: LocalConfig{TunMTU: 8500}}
		applyDefaults(cfg)
		if got := cfg.TunMTU(); got != 8500 {
			t.Errorf("TunMTU() = %d, want 8500 (a valid value must survive normalization)", got)
		}
	})

	t.Run("简单模式构建与覆盖", func(t *testing.T) {
		// BuildSimpleConfig 末尾会调用 applyDefaults，因此越界值同样在构建时就
		// 被钳制（与 TestTimeoutClampedOnEveryEntry 对 timeout 的要求一致）。
		built, err := BuildSimpleConfig(&config.SimpleConfig{
			Server: "example.com", Password: "secret", TunMTU: 60000,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if built.Local.TunMTU != config.MaxTunMTU {
			t.Errorf("built Local.TunMTU = %d, want %d (clamped)", built.Local.TunMTU, config.MaxTunMTU)
		}

		valid, err := BuildSimpleConfig(&config.SimpleConfig{
			Server: "example.com", Password: "secret", TunMTU: 8500,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := valid.TunMTU(); got != 8500 {
			t.Errorf("built TunMTU() = %d, want 8500 (a valid value must survive normalization)", got)
		}

		overridden := testDefaultConfig()
		if err := ApplySimpleOverrides(overridden, &config.SimpleConfig{TunMTU: 100}); err != nil {
			t.Fatal(err)
		}
		if overridden.Local.TunMTU != config.MinTunMTU {
			t.Errorf("overridden Local.TunMTU = %d, want %d (clamped)", overridden.Local.TunMTU, config.MinTunMTU)
		}

		// 未提供覆盖值时不得改动已有配置：0 表示"未配置"，而不是"设成默认值"。
		untouched := &ClientConfig{Local: LocalConfig{TunMTU: 8500}}
		if err := ApplySimpleOverrides(untouched, &config.SimpleConfig{}); err != nil {
			t.Fatal(err)
		}
		if got := untouched.TunMTU(); got != 8500 {
			t.Errorf("TunMTU() = %d, want 8500 (an empty override must not reset it)", got)
		}
	})
}
