package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
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
	cfg := DefaultConfig()
	cfg.Servers = []*ServerProfile{
		{Address: "example.com", Port: 443, Password: "secret", Default: true},
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
	if clone.Servers[0].Address != cfg.Servers[0].Address {
		t.Error("Server address mismatch")
	}

	// 验证深拷贝：修改 clone 不影响原对象
	clone.Servers[0].Port = 8443
	if cfg.Servers[0].Port == 8443 {
		t.Error("Clone did not deep copy servers")
	}
}

func TestDefaultServer(t *testing.T) {
	tests := []struct {
		name    string
		servers []*ServerProfile
		want    string // 期望返回的 Address，空表示 nil
	}{
		{
			name:    "空服务器列表",
			servers: nil,
			want:    "",
		},
		{
			name: "有默认标记的服务器",
			servers: []*ServerProfile{
				{Address: "s1.example.com", Default: false},
				{Address: "s2.example.com", Default: true},
				{Address: "s3.example.com", Default: false},
			},
			want: "s2.example.com",
		},
		{
			name: "无默认标记时返回第一个",
			servers: []*ServerProfile{
				{Address: "s1.example.com", Default: false},
				{Address: "s2.example.com", Default: false},
			},
			want: "s1.example.com",
		},
		{
			name: "多个默认标记时返回第一个",
			servers: []*ServerProfile{
				{Address: "s1.example.com", Default: true},
				{Address: "s2.example.com", Default: true},
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
				if srv.Address != tt.want {
					t.Errorf("Address = %q, want %q", srv.Address, tt.want)
				}
			}
		})
	}
}

func TestServerURL(t *testing.T) {
	t.Run("有默认服务器", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Address: "example.com", Port: 443, Default: true},
			},
		}
		if url := cfg.ServerURL(); url != "https://example.com:443" {
			t.Errorf("ServerURL = %q, want https://example.com:443", url)
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
			{Address: "s1.example.com"},
			{Address: "s2.example.com"},
			{Address: "s3.example.com"},
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
				{Address: "s1.example.com", Port: 443},
				{Address: "s2.example.com", Port: 8443},
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
				{Address: "example.com", Port: 443, Default: true},
			},
		}
		if addr := cfg.DefaultServerAddr(); addr != "example.com:443" {
			t.Errorf("DefaultServerAddr = %q", addr)
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
				{Address: "s1.example.com"},
				{Address: "s2.example.com", Default: true},
			},
		}
		if idx := cfg.DefaultServerIndex(); idx != 1 {
			t.Errorf("DefaultServerIndex = %d, want 1", idx)
		}
	})

	t.Run("无默认标记返回0", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Address: "s1.example.com"},
				{Address: "s2.example.com"},
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

func TestMigrateV2Config(t *testing.T) {
	t.Run("完整 v2 配置迁移", func(t *testing.T) {
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

		v3, err := MigrateV2Config(v2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if v3.ConfigVersion != 3 {
			t.Errorf("ConfigVersion = %d", v3.ConfigVersion)
		}
		if v3.Servers[0].Address != "example.com" {
			t.Errorf("Address = %q", v3.Servers[0].Address)
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

	t.Run("v2 配置默认值填充", func(t *testing.T) {
		v2 := config.SimpleConfig{
			Server:   "example.com",
			Password: "secret",
		}

		v3, err := MigrateV2Config(v2)
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

	t.Run("v2 HTTPPort 自动计算", func(t *testing.T) {
		v2 := config.SimpleConfig{
			Server:    "example.com",
			Password:  "secret",
			LocalPort: 1080,
			// HTTPPort 未设置
		}

		v3, err := MigrateV2Config(v2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if v3.Local.HTTPPort != 2080 {
			t.Errorf("HTTPPort = %d, want 2080 (SocksPort + 1000)", v3.Local.HTTPPort)
		}
	})

	t.Run("v2 OutboundProto 校验", func(t *testing.T) {
		v2 := config.SimpleConfig{
			Server:        "example.com",
			Password:      "secret",
			OutboundProto: "invalid",
		}

		_, err := MigrateV2Config(v2)
		if err == nil {
			t.Error("expected error for invalid outbound_proto")
		}
	})
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
			"servers": [{"address": "example.com", "port": 443, "password": "secret", "default": true}],
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
		if cfg.Servers[0].Address != "example.com" {
			t.Errorf("Address = %q", cfg.Servers[0].Address)
		}
		if cfg.Routing.ProxyRule != "proxy" {
			t.Errorf("ProxyRule = %q", cfg.Routing.ProxyRule)
		}
		if cfg.Log.Level != "debug" {
			t.Errorf("LogLevel = %q", cfg.Log.Level)
		}
	})

	t.Run("加载 v2 配置自动迁移", func(t *testing.T) {
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
		if cfg.Servers[0].Address != "example.com" {
			t.Errorf("Address = %q", cfg.Servers[0].Address)
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

	// VPN 声明的中继数量上限是启动期的硬约束：越限的配置没有可工作的形态
	// （见 ValidateDERPRelays），必须在 LoadConfig 就拒绝，而不是启动之后才发现
	// 某些中继连不上。反过来，VPN 未启用时这些标记不参与运行期，不该阻止启动。
	t.Run("VPN 声明的中继超过上限时拒绝启动", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		v3JSON := `{
			"version": 3,
			"servers": [
				{"address": "a.example.com", "port": 443, "password": "p", "default": true},
				{"address": "b.example.com", "port": 443, "password": "p", "derp": true},
				{"address": "c.example.com", "port": 443, "password": "p", "derp": true},
				{"address": "d.example.com", "port": 443, "password": "p", "derp": true},
				{"address": "e.example.com", "port": 443, "password": "p", "derp": true}
			],
			"vpn": {"enabled": true}
		}`
		if err := os.WriteFile(path, []byte(v3JSON), 0644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatal("LoadConfig accepted 4 declared DERP relays, want a refusal")
		}
		for _, want := range []string{"4 DERP relays", "at most 3 relays", "derp"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should mention %q", err, want)
			}
		}
	})

	t.Run("VPN 未启用时过多的 derp 标记不阻止启动", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		v3JSON := `{
			"version": 3,
			"servers": [
				{"address": "a.example.com", "port": 443, "password": "p", "default": true},
				{"address": "b.example.com", "port": 443, "password": "p", "derp": true},
				{"address": "c.example.com", "port": 443, "password": "p", "derp": true},
				{"address": "d.example.com", "port": 443, "password": "p", "derp": true},
				{"address": "e.example.com", "port": 443, "password": "p", "derp": true}
			]
		}`
		if err := os.WriteFile(path, []byte(v3JSON), 0644); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("unexpected error while the VPN is disabled: %v", err)
		}
		if cfg.VPN.Enabled {
			t.Error("VPN.Enabled = true for a config without a vpn key")
		}
	})
}

func TestMigrateV2ToV3(t *testing.T) {
	dir := t.TempDir()

	v2Path := filepath.Join(dir, "v2_config.json")
	v2JSON := `{
		"server": "example.com",
		"server_port": 443,
		"password": "secret",
		"local_port": 1080
	}`
	if err := os.WriteFile(v2Path, []byte(v2JSON), 0644); err != nil {
		t.Fatal(err)
	}

	v3Path := filepath.Join(dir, "v3_config.json")
	if err := MigrateV2ToV3(v2Path, v3Path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 验证 v3 文件存在且内容正确
	data, err := os.ReadFile(v3Path)
	if err != nil {
		t.Fatal(err)
	}

	var v3 ClientConfig
	if err := json.Unmarshal(data, &v3); err != nil {
		t.Fatal(err)
	}
	if v3.ConfigVersion != 3 {
		t.Errorf("ConfigVersion = %d", v3.ConfigVersion)
	}
	if v3.Servers[0].Address != "example.com" {
		t.Errorf("Address = %q", v3.Servers[0].Address)
	}
}

func TestApplyDefaults(t *testing.T) {
	t.Run("填充所有默认值", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Address: "example.com"},
				{Address: "example2.com"},
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
		cfg := &ClientConfig{Shaper: ShaperConfig{BatchWindowMS: 100}}
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
			Log: LogConfig{Level: "error"},
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
				{Address: "example.com"},
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
				{Address: "example.com"},
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
		ApplySimpleOverrides(cfg, &config.SimpleConfig{Timeout: 1})
		if cfg.Timeout != config.MinTimeout {
			t.Errorf("Timeout = %d, want clamped to %d", cfg.Timeout, config.MinTimeout)
		}

		// 未提供覆盖（0）时保持配置中的值，不会被当成"钳制到下限"。
		ApplySimpleOverrides(cfg, &config.SimpleConfig{})
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
		cfg := DefaultConfig()
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
			"servers": [{"address": "example.com", "port": 443, "password": "secret", "default": true}],
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

		overridden := DefaultConfig()
		ApplySimpleOverrides(overridden, &config.SimpleConfig{TunMTU: 100})
		if overridden.Local.TunMTU != config.MinTunMTU {
			t.Errorf("overridden Local.TunMTU = %d, want %d (clamped)", overridden.Local.TunMTU, config.MinTunMTU)
		}

		// 未提供覆盖值时不得改动已有配置：0 表示"未配置"，而不是"设成默认值"。
		untouched := &ClientConfig{Local: LocalConfig{TunMTU: 8500}}
		ApplySimpleOverrides(untouched, &config.SimpleConfig{})
		if got := untouched.TunMTU(); got != 8500 {
			t.Errorf("TunMTU() = %d, want 8500 (an empty override must not reset it)", got)
		}
	})
}

// lockedLogBuffer / captureLogs 把 easyss 的日志器换成写入内存的 slog，供
// "残留的已移除字段会被告警"这类测试断言（恢复由 t.Cleanup 完成）。
type lockedLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedLogBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func captureLogs(t *testing.T) *lockedLogBuffer {
	t.Helper()
	buf := new(lockedLogBuffer)
	prev := log.Logger()
	log.SetLogger(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { log.SetLogger(prev) })
	return buf
}

// TestLoadConfigWarnsOnRemovedDERPAddr 固定已移除字段的降级行为：配置里残留的
// vpn.derp_addr 是未知键（json.Unmarshal 直接忽略），既不影响节点通告的中继列表，
// 也不会让加载失败，但必须在启动日志里说清楚——"以为中继在别的 host:port"正是
// 那种配置照常加载、VPN 却一直连不上的情形。
func TestLoadConfigWarnsOnRemovedDERPAddr(t *testing.T) {
	logs := captureLogs(t)

	path := filepath.Join(t.TempDir(), "config.json")
	body := `{
		"version": 3,
		"servers": [
			{"address": "a.example.com", "port": 443, "password": "p", "default": true},
			{"address": "relay.example.com", "port": 8443, "password": "p", "derp": true}
		],
		"vpn": {"enabled": true, "derp_addr": "relay.internal:9443"}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got, want := cfg.VPNDERPAddr(), "relay.example.com:8443"; got != want {
		t.Errorf("VPNDERPAddr() = %q, want %q: the removed key must not influence the relay list", got, want)
	}

	out := logs.String()
	if !strings.Contains(out, "vpn.derp_addr was removed") {
		t.Errorf("the load log does not report the removed key:\n%s", out)
	}
	if !strings.Contains(out, "relay.internal:9443") {
		t.Errorf("the load log does not name the ignored value:\n%s", out)
	}
}

// TestLoadConfigWithoutDERPAddrKeyStaysQuiet 守护告警不误报：没有那个键的配置
// 不该出现任何相关日志。
func TestLoadConfigWithoutDERPAddrKeyStaysQuiet(t *testing.T) {
	logs := captureLogs(t)

	path := filepath.Join(t.TempDir(), "config.json")
	body := `{
		"version": 3,
		"servers": [{"address": "a.example.com", "port": 443, "password": "p", "default": true, "derp": true}],
		"vpn": {"enabled": true}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if out := logs.String(); strings.Contains(out, "derp_addr") {
		t.Errorf("the load log mentions derp_addr although the config does not use it:\n%s", out)
	}
}
