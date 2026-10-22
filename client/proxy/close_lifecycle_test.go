package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
)

// closeLifecycleBudget 把"永久挂住"变成一次快速失败；正常路径远小于该值。
const closeLifecycleBudget = 10 * time.Second

// closeIdempotentBudget 是第二次 Close 的耗时上限：幂等路径只是 sync.Once 命中，
// 但会被调度延迟拉长，因此不按微秒断言。
const closeIdempotentBudget = 500 * time.Millisecond

// freeLoopbackAddr 返回一个当前无人监听的 127.0.0.1 地址，端口由内核挑选以免并发测试争抢。
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close() //nolint:errcheck
	return addr
}

// TestHTTPProxyCloseBeforeStartReleasesListener 固定 Close 先于 Start 的时序：迟到的 Start 必须自己
// 关掉刚绑定的监听器并返回 http.ErrServerClosed。runner 在 goroutine 里派发 Start，核心可能随即被停止
// 并再次启动，泄漏的监听器会让重启以 "address already in use" 失败。
func TestHTTPProxyCloseBeforeStartReleasesListener(t *testing.T) {
	addr := freeLoopbackAddr(t)
	srv, err := NewHTTPProxyServer(HTTPProxyOptions{
		ListenAddr: addr,
		SocksAddr:  "127.0.0.1:1",
		Timeouts:   config.Timeouts{Base: time.Second},
	})
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}

	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()

	select {
	case err := <-startDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Start after Close: got %v, want %v", err, http.ErrServerClosed)
		}
	case <-time.After(closeLifecycleBudget):
		t.Fatal("Start after Close kept serving (listener leaked, port held forever)")
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port %s is still held after Close: %v", addr, err)
	}
	l.Close() //nolint:errcheck
}

// TestHTTPProxyCloseIsIdempotent 固定 Close 的幂等性：第二次调用不得再次 Shutdown（会重复等待在飞请求）。
func TestHTTPProxyCloseIsIdempotent(t *testing.T) {
	srv, err := NewHTTPProxyServer(HTTPProxyOptions{
		ListenAddr: freeLoopbackAddr(t),
		SocksAddr:  "127.0.0.1:1",
		Timeouts:   config.Timeouts{Base: time.Second},
	})
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestSocks5CloseIsIdempotent 固定 Socks5Server.Close 的幂等性：第二次调用必须立即
// no-op 并原样返回首次结果。更新重启失败的恢复流程会连调两次 closeService()
// （见 cmd/easyss/internal/tray/update.go）。
func TestSocks5CloseIsIdempotent(t *testing.T) {
	srv := newTestSocks5Server(t, freeLoopbackAddr(t))
	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()

	// 等 Start 真正绑上端口，让第一次 Close 覆盖"服务器已在运行"这条路径。
	if err := waitListenerUp(srv.listenAddr, closeLifecycleBudget); err != nil {
		t.Fatal(err)
	}

	firstErr := srv.Close()
	if firstErr != nil {
		t.Fatalf("first Close: %v", firstErr)
	}

	start := time.Now()
	secondErr := srv.Close()
	elapsed := time.Since(start)
	if secondErr != firstErr {
		t.Fatalf("second Close = %v, want the cached first result %v", secondErr, firstErr)
	}
	if elapsed > closeIdempotentBudget {
		t.Fatalf("second Close took %s, want an immediate no-op (<= %s)", elapsed, closeIdempotentBudget)
	}

	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start after Close: %v", err)
		}
	case <-time.After(closeLifecycleBudget):
		t.Fatal("Start did not return after Close (listener leaked)")
	}
	if err := waitListenerGone(srv.listenAddr, closeFastReleaseBudget); err != nil {
		t.Fatal(err)
	}
}

func waitListenerUp(addr string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close() //nolint:errcheck
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("socks5 listener on %s never came up within %s", addr, budget)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// socks5Stub 是最小的 SOCKS5 服务端桩：完成无认证握手与 CONNECT 应答，回一个最小 HTTP 响应后保持
// 连接打开。它记录当前打开的连接数，使"连接池有没有被关闭"可以被直接观测。
type socks5Stub struct {
	ln     net.Listener
	open   atomic.Int64
	closed chan struct{}
}

func startSocks5Stub(t *testing.T) (*socks5Stub, string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}
	stub := &socks5Stub{ln: ln, closed: make(chan struct{}, 64)}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go stub.serve(conn)
		}
	}()
	return stub, ln.Addr().String()
}

func (s *socks5Stub) serve(conn net.Conn) {
	s.open.Add(1)
	defer func() {
		s.open.Add(-1)
		_ = conn.Close()
		select {
		case s.closed <- struct{}{}:
		default:
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 握手：VER + NMETHODS + METHODS。
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 请求：VER + CMD + RSV + ATYP + ADDR + PORT。
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	switch req[3] {
	case 0x01:
		var rest [6]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			return
		}
	case 0x03:
		var ln [1]byte
		if _, err := io.ReadFull(conn, ln[:]); err != nil {
			return
		}
		var rest [2]byte
		if _, err := io.ReadFull(conn, make([]byte, int(ln[0])+len(rest))); err != nil {
			return
		}
	case 0x04:
		var rest [18]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			return
		}
	default:
		return
	}
	// 成功应答：BND.ADDR = 0.0.0.0:0。
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 回一个最小 HTTP 响应，让反向代理的请求成功返回。
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		return
	}

	// keep-alive：客户端会把它放回连接池，只有池被关闭时这里才读到 EOF。
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

// TestHTTPProxyCloseReleasesReverseProxyIdleConns 固定 Close 关闭自己创建的连接池：反向代理的
// http.Transport 拨的是本地 SOCKS5 入口，每条空闲连接都占着一个 SOCKS5 handler 与一条隧道流。
func TestHTTPProxyCloseReleasesReverseProxyIdleConns(t *testing.T) {
	stub, socksAddr := startSocks5Stub(t)

	srv, err := NewHTTPProxyServer(HTTPProxyOptions{
		ListenAddr: freeLoopbackAddr(t),
		SocksAddr:  socksAddr,
		Timeouts:   config.Timeouts{Base: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}
	go srv.Start() //nolint:errcheck

	proxyURL, err := url.Parse("http://" + srv.listenAddr)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	defer client.CloseIdleConnections()

	var resp *http.Response
	deadline := time.Now().Add(closeLifecycleBudget)
	for {
		resp, err = client.Get("http://example.com/")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("request through the http proxy never succeeded: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unexpected response: %d %q", resp.StatusCode, body)
	}

	if !waitForStubConns(t, stub, 1) {
		t.Fatal("reverse proxy did not pool its SOCKS5 connection")
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close 之后空闲连接必须被回收，否则一直占着 SOCKS5 侧的资源。
	if !waitForStubConns(t, stub, 0) {
		t.Fatal("Close left the reverse proxy's idle SOCKS5 connection open")
	}
}

func waitForStubConns(t *testing.T, stub *socks5Stub, want int64) bool {
	t.Helper()

	deadline := time.Now().Add(closeLifecycleBudget)
	for {
		if got := stub.open.Load(); got == want {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-stub.closed:
		case <-time.After(20 * time.Millisecond):
		}
	}
}
