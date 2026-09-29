package selfupdate

import (
	"net/http"
	"testing"
)

// TestNewClientBoundsIdleConnections 固定获取客户端的连接池上限。
//
// 托盘是长驻进程，每次检查（启动后一次、每 24 小时一次、每次手动点击）都会新建
// 一个 Client；本地 HTTP 代理侧没有 IdleTimeout，因此传输层如果没有
// IdleConnTimeout，每条 keep-alive 连接都会永久占住一条隧道流与两个 goroutine。
func TestNewClientBoundsIdleConnections(t *testing.T) {
	c := NewClient(8080)
	t.Cleanup(c.Close)

	if c.proxy == nil || c.direct == nil {
		t.Fatal("expected both the proxy and the direct client to be configured")
	}

	for name, hc := range map[string]*http.Client{"proxy": c.proxy, "direct": c.direct} {
		tr, ok := hc.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("%s client: unexpected transport type %T", name, hc.Transport)
		}
		if tr.IdleConnTimeout <= 0 {
			t.Fatalf("%s transport has no IdleConnTimeout: idle connections would never be reaped", name)
		}
	}
}

// TestClientCloseIsRepeatable 固定 Close 的可重复调用：检查路径会 defer 它，
// 而调用方也可能再关一次。
func TestClientCloseIsRepeatable(t *testing.T) {
	c := NewClient(8080)
	c.Close()
	c.Close()

	// 未配置本地代理端口时只有直连客户端，同样必须可以关闭。
	directOnly := NewClient(0)
	if directOnly.proxy != nil {
		t.Fatal("expected no proxy client when localHTTPPort <= 0")
	}
	directOnly.Close()
	directOnly.Close()

	var nilClient *Client
	nilClient.Close() // 不得 panic
}
