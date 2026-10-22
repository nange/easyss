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
