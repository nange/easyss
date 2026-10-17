package main

import (
	"strings"
	"testing"
)

// TestExampleV3ConfigUsesHost 固定 -show-config-example 的完整模式示例输出
// 新键 host；旧键 address 不应再出现在示例里。
func TestExampleV3ConfigUsesHost(t *testing.T) {
	out := exampleV3Config()
	if !strings.Contains(out, `"host"`) {
		t.Errorf("full config example should contain host: %s", out)
	}
	if strings.Contains(out, `"address"`) {
		t.Errorf("full config example must not contain address: %s", out)
	}
}
