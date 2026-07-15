package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nange/easyss/v3/config"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.ConfigVersion != 3 {
		t.Errorf("ConfigVersion = %d, want 3", cfg.ConfigVersion)
	}
	if cfg.Local.SocksPort != 2080 {
		t.Errorf("SocksPort = %d, want 2080", cfg.Local.SocksPort)
	}
	if cfg.Local.HTTPPort != 3080 {
		t.Errorf("HTTPPort = %d, want 3080", cfg.Local.HTTPPort)
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
		v2 := V2Config{
			Server:           "example.com",
			ServerPort:       443,
			Password:         "secret",
			Method:           "aes-256-gcm",
			SN:               "sni.example.com",
			LocalPort:        1080,
			HTTPPort:         2080,
			BindALL:          true,
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
		v2 := V2Config{
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
		v2 := V2Config{
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
		v2 := V2Config{
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
		{"", "", false},
		{"native", "", false},
		{"h2", "h2", false},
		{"invalid", "", true},
		{"H2", "", true}, // 大小写敏感
	}

	for _, tt := range tests {
		t.Run(tt.proto, func(t *testing.T) {
			got, err := outboundProtoToProtocol(tt.proto)
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
		if cfg.Shaper.BatchWindowMS != config.DefaultBatchWindowMS {
			t.Errorf("BatchWindowMS = %d", cfg.Shaper.BatchWindowMS)
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

	t.Run("BatchWindowMS 上限", func(t *testing.T) {
		cfg := &ClientConfig{Shaper: ShaperConfig{BatchWindowMS: 100}}
		applyDefaults(cfg)
		if cfg.Shaper.BatchWindowMS != 10 {
			t.Errorf("BatchWindowMS = %d, want 10 (capped)", cfg.Shaper.BatchWindowMS)
		}
	})

	t.Run("已有值不被覆盖", func(t *testing.T) {
		cfg := &ClientConfig{
			Timeout: 120,
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

		if cfg.Timeout != 120 {
			t.Errorf("Timeout = %d, want 120 (not overwritten)", cfg.Timeout)
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
}
