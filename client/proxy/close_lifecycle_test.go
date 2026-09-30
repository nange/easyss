package proxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
)

// closeLifecycleBudget 是"关闭/启动必须在预算内返回"的上限。它的唯一作用是
// 把"永久挂住"变成一次快速失败：正常路径远小于该值。
const closeLifecycleBudget = 10 * time.Second

// closeIdempotentBudget 是第二次 Close 允许消耗的时间上限。幂等路径只是一次
// sync.Once 命中，但它仍会被调度延迟拉长，因此不按微秒断言；重新探测至少要等满
// acceptProbeTimeout（3s），依旧会被这个上限抓住。
const closeIdempotentBudget = 500 * time.Millisecond

// freeLoopbackAddr 返回一个当前无人监听的 127.0.0.1 地址。端口由内核挑选，
// 因此同一台机器上的并发测试不会互相争抢。
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

// TestHTTPProxyCloseBeforeStartReleasesListener 固定"Close 先于 Start"这一时序：
// 迟到的 Start 必须自己关掉刚绑定的监听器并返回 http.ErrServerClosed，而不是让
// 一个无人引用的服务器永久占用端口。
//
// 这不是假想时序：runner 在 goroutine 中派发 Start（runner.Run），核心可能随即
// 被停止（托盘切换服务器、mobile.Stop），随后同一个进程会再次启动核心——端口
// 如果被泄漏的服务器占着，重启就会以 "address already in use" 失败。
// 旧形态下本测试会在预算耗尽时失败（Start 永久阻塞在 Serve 上）。
func TestHTTPProxyCloseBeforeStartReleasesListener(t *testing.T) {
	addr := freeLoopbackAddr(t)
	srv, err := NewHTTPProxyServer(HTTPProxyOptions{
		ListenAddr: addr,
		SocksAddr:  "127.0.0.1:1",
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}

	// Close 先于 Start：此时还没有监听器，Close 必须是安全的。
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

	// 端口必须可以立刻重新绑定。
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port %s is still held after Close: %v", addr, err)
	}
	l.Close() //nolint:errcheck
}

// TestHTTPProxyCloseIsIdempotent 固定 Close 的幂等性：第二次调用不得再次
// Shutdown（那会重复等待在飞请求），也不得 panic。
func TestHTTPProxyCloseIsIdempotent(t *testing.T) {
	srv, err := NewHTTPProxyServer(HTTPProxyOptions{
		ListenAddr: freeLoopbackAddr(t),
		SocksAddr:  "127.0.0.1:1",
		Timeout:    time.Second,
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

// TestSocks5CloseIsIdempotent 固定 Socks5Server.Close 的幂等性。旧形态下第二次
// Close 会重新走 shutdown：accept 探测在已关闭的监听地址上必然失败，于是阻塞
// acceptProbeTimeout（3s）并留下一个 30s 的后台补关闭 goroutine。
//
// 这条路径在托盘上是可达的：更新重启失败后的恢复路径会先 closeService()，
// restartService() 又会 closeService() 一次（见 cmd/easyss/tray_update.go）。
//
// 断言刻意与"这一次探测有没有答上"无关：单次探测预算只有 3s，在 -race 且多个
// 测试包并行的 CI runner 上曾被调度延迟耗尽（2026-09-29 的 windows/amd64 job
// 就是这样失败的）。因此这里先等 accept 循环就绪，让第一次 Close 走同步路径；
// 而幂等性本身只要求第二次返回与第一次相同的结果——探测没答上时那就是同一个
// errAcceptNotReady，不是"必须为 nil"。
func TestSocks5CloseIsIdempotent(t *testing.T) {
	addr := freeLoopbackAddr(t)
	srv, err := NewSocks5Server(Socks5Options{
		ListenAddr: addr,
		Handler:    newTestStreamHandler(&mockTransport{}),
		Method:     protocol.MethodAES256GCM,
		Timeouts: config.Timeouts{
			Base:       30 * time.Second,
			Dial:       10 * time.Second,
			StreamIdle: 30 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	srv.MarkStarted()
	go srv.Start() //nolint:errcheck

	// 先等 accept 循环真正开始应答：这样第一次 Close 通常落在同步 Shutdown 路径上
	// （而不是碰运气命中 3s 探测预算）；万一探测仍然没答上，也只是转走补关闭，
	// 由下面的"返回首次结果"断言覆盖，不会变成失败。
	if !srv.waitForAcceptWithin(closeLifecycleBudget) {
		t.Fatal("accept loop did not become ready in time")
	}

	firstErr := srv.Close()
	if firstErr != nil && !errors.Is(firstErr, errAcceptNotReady) {
		t.Fatalf("first Close: %v", firstErr)
	}

	// 第二次 Close 必须原样返回首次的结果：既不重新探测，也不派发第二个补关闭
	// goroutine。
	start := time.Now()
	secondErr := srv.Close()
	elapsed := time.Since(start)
	if secondErr != firstErr {
		t.Fatalf("second Close = %v, want the cached first result %v", secondErr, firstErr)
	}
	if elapsed > closeIdempotentBudget {
		t.Fatalf("second Close took %s, want an immediate no-op (<= %s)", elapsed, closeIdempotentBudget)
	}
}

// socks5Stub 是最小的 SOCKS5 服务端桩：完成无认证握手与 CONNECT 应答，回一个
// 最小 HTTP 响应，然后把连接保持打开，直到对端关闭。它记录当前打开的连接数，
// 使"连接池有没有被关闭"可以被直接观测（见 TestHTTPProxyCloseReleases...）。
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

	// 保持连接（keep-alive）：客户端会把它放回连接池，只有连接池被关闭时
	// 这里才会读到 EOF。
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

// TestHTTPProxyCloseReleasesReverseProxyIdleConns 固定"Close 关闭自己创建的
// 连接池"：反向代理的 http.Transport 拨的是本地 SOCKS5 入口，池中的每条空闲
// 连接都占着一个 SOCKS5 侧 handler 与一条隧道流。旧形态只关监听器，这个连接池
// 无人可达、永远不回收。
func TestHTTPProxyCloseReleasesReverseProxyIdleConns(t *testing.T) {
	stub, socksAddr := startSocks5Stub(t)

	srv, err := NewHTTPProxyServer(HTTPProxyOptions{
		ListenAddr: freeLoopbackAddr(t),
		SocksAddr:  socksAddr,
		Timeout:    5 * time.Second,
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

	// 普通 HTTP 请求（非 CONNECT）走反向代理路径：HTTP 入口 -> SOCKS5 隧道。
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

	// 请求结束后连接应回到反向代理自己的连接池里。
	if !waitForStubConns(t, stub, 1) {
		t.Fatal("reverse proxy did not pool its SOCKS5 connection")
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close 之后空闲连接必须被回收，否则它会一直占着 SOCKS5 侧的资源。
	if !waitForStubConns(t, stub, 0) {
		t.Fatal("Close left the reverse proxy's idle SOCKS5 connection open")
	}
}

// waitForStubConns 等待桩上的打开连接数降到 want（或达到 want 的稳定状态）。
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
