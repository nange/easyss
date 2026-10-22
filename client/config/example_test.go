package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExampleConfigUsesHost 固定 -show-config-example 的完整模式示例输出
// 新键 host；旧键 address 不应再出现在示例里。
func TestExampleConfigUsesHost(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(ExampleConfig())
	if err != nil {
		t.Fatalf("marshal example config: %v", err)
	}
	out := string(b)
	if !strings.Contains(out, `"host"`) {
		t.Errorf("full config example should contain host: %s", out)
	}
	if strings.Contains(out, `"address"`) {
		t.Errorf("full config example must not contain address: %s", out)
	}
}

// TestExampleConfigRoundTrips 固定示例本身能被正式解析路径接受，字段漂移会让这里失败；
// 与 server 侧“示例本身已归一化”的测试对称。
func TestExampleConfigRoundTrips(t *testing.T) {
	t.Parallel()

	example := ExampleConfig()
	b, err := json.Marshal(example)
	if err != nil {
		t.Fatalf("marshal example config: %v", err)
	}
	cfg, err := ParseConfigJSON(string(b))
	if err != nil {
		t.Fatalf("example config must parse: %v", err)
	}
	if got, want := cfg.DefaultServerAddr(), example.DefaultServerAddr(); got != want {
		t.Errorf("default server = %q, want %q", got, want)
	}
	if got, want := cfg.Local.HTTPPort, example.Local.HTTPPort; got != want {
		t.Errorf("http port = %d, want %d", got, want)
	}

	simple := ExampleSimpleConfig()
	if _, err := BuildSimpleConfig(&simple); err != nil {
		t.Fatalf("simple example must build: %v", err)
	}
}
