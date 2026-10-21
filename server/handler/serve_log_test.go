package handler

import (
	"testing"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/server/nextproxy"
)

// TestSessionLogAttrsIncludesNextProxy 固定入口日志的可见性：成功的 TCP 结果
// 日志是 Debug，如果入口也不带 via_next_proxy，默认 Info 级别就完全看不出
// 一条成功的流走了下一级代理。
func TestSessionLogAttrsIncludesNextProxy(t *testing.T) {
	np, err := nextproxy.New("socks5://127.0.0.1:1080", false, true)
	if err != nil {
		t.Fatalf("create next proxy: %v", err)
	}

	h := NewProxyHandler(ProxyHandlerConfig{NextProxy: np})
	attrs := h.sessionLogAttrs(handshakeResult{
		endpoint: config.EndpointTCP,
		target:   "example.com:443",
	}, "client:1234")

	if got := attrValue(attrs, "via_next_proxy"); got != true {
		t.Fatalf("via_next_proxy = %v, want true; attrs=%v", got, attrs)
	}
	if got := attrValue(attrs, "proxy"); got != "127.0.0.1:1080" {
		t.Fatalf("proxy = %v, want 127.0.0.1:1080; attrs=%v", got, attrs)
	}
}

// TestSessionLogAttrsOmitsRouteForDirectAndUDP 固定两个边界：直连 TCP 不添加
// 路由字段；UDP 的目标是解析器，真正的路由要等第一帧 QNAME 才能判定，入口
// 不能提前声称它走代理（UDP 侧由 [UDP] upstream connected 记录）。
func TestSessionLogAttrsOmitsRouteForDirectAndUDP(t *testing.T) {
	np, err := nextproxy.New("socks5://127.0.0.1:1080", false, true)
	if err != nil {
		t.Fatalf("create next proxy: %v", err)
	}
	h := NewProxyHandler(ProxyHandlerConfig{NextProxy: np})

	udpAttrs := h.sessionLogAttrs(handshakeResult{
		endpoint: config.EndpointUDP,
		target:   "8.8.8.8:53",
	}, "client:1234")
	if got := attrValue(udpAttrs, "via_next_proxy"); got != nil {
		t.Fatalf("UDP via_next_proxy = %v, want absent; attrs=%v", got, udpAttrs)
	}

	direct, err := nextproxy.New("socks5://127.0.0.1:1080", false, false)
	if err != nil {
		t.Fatalf("create next proxy: %v", err)
	}
	directHandler := NewProxyHandler(ProxyHandlerConfig{NextProxy: direct})
	directAttrs := directHandler.sessionLogAttrs(handshakeResult{
		endpoint: config.EndpointTCP,
		target:   "example.com:443",
	}, "client:1234")
	if got := attrValue(directAttrs, "via_next_proxy"); got != nil {
		t.Fatalf("direct TCP via_next_proxy = %v, want absent; attrs=%v", got, directAttrs)
	}
}

func attrValue(attrs []any, key string) any {
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == key {
			return attrs[i+1]
		}
	}
	return nil
}
