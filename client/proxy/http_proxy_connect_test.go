package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
)

// 直连拨号失败时必须在隧道建立前回一个 502：只关闭 hijack 到的连接会让客户端看到空应答。
func TestConnectDirectDialFailureRepliesBadGateway(t *testing.T) {
	rt, err := router.New(router.Config{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddDirectDomain("direct.test")

	s, err := NewHTTPProxyServer(HTTPProxyOptions{
		ListenAddr: "127.0.0.1:0",
		SocksAddr:  "127.0.0.1:1",
		Router:     rt,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
		Timeouts: config.Timeouts{},
	})
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Close() })

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := fmt.Fprintf(conn, "CONNECT direct.test:443 HTTP/1.1\r\nHost: direct.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}
