package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair 建立一对全新的本地 TCP 连接（客户端侧 + 被接受的服务器侧）并返回两端。
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		accepted <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() }) //nolint:errcheck

	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		client.Close() //nolint:errcheck
		t.Fatal("accept timed out")
	}
	t.Cleanup(func() { server.Close() }) //nolint:errcheck
	return client, server
}

// connClosed 报告连接是否已关闭：对已关闭的 TCP 连接执行读操作会返回错误
// （半关闭的 FIN/EOF 之后也是如此，这也证明不再有数据流动）。
func connClosed(t *testing.T, conn net.Conn) bool {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	return err != nil
}

// TestRelayTCPIdleTimeoutClosesBoth 验证 relayTCP 遵守其 idle 超时参数：一对静默的
// 连接必须在给定的 idle 时间后被拆除（两端连接均关闭），这样拷贝协程才不会永远挂起。
func TestRelayTCPIdleTimeoutClosesBoth(t *testing.T) {
	client, server := tcpPair(t)

	const idle = 100 * time.Millisecond
	start := time.Now()
	relayTCP(client, server, idle)
	if elapsed := time.Since(start); elapsed < idle {
		t.Fatalf("relay returned after %v, want >= %v idle", elapsed, idle)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("relay took %v, want ~%v", elapsed, idle)
	}
	if !connClosed(t, client) {
		t.Error("client connection still open after idle timeout")
	}
	if !connClosed(t, server) {
		t.Error("server connection still open after idle timeout")
	}
}

// TestRelayTCPHalfCloseAndCompletion 以贴近真实的拓扑验证直连中继的半关闭语义：
// 两对独立的 TCP 连接分别模拟"本地应用 <-> 代理"和"代理 <-> 远端服务器"两段，
// 由中继桥接代理侧的两个 socket。每个 socket 恰好有一个读方和一个写方，与生产环境
// 一致。一段的 FIN 通过 CloseWrite 传播到另一端，同时反向方向继续传输；只有两个
// 方向都完成后（代理侧两个 socket 都已关闭），中继才返回。
func TestRelayTCPHalfCloseAndCompletion(t *testing.T) {
	app, proxyC := tcpPair(t)     // 本地应用 <-> 代理
	proxyRC, remote := tcpPair(t) // 代理 <-> 远端服务器

	done := make(chan struct{})
	go func() {
		relayTCP(proxyRC, proxyC, time.Minute) // 与 TCPHandle 相同的参数方向
		close(done)
	}()

	// 应用发送其负载并半关闭写侧：中继必须把 FIN 转发给远端（CloseWrite），
	// 同时保持"远端 -> 应用"方向存活。
	if _, err := app.Write([]byte("hello")); err != nil {
		t.Fatalf("app write: %v", err)
	}
	if err := app.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("app CloseWrite: %v", err)
	}

	buf := make([]byte, 5)
	if _, err := io.ReadFull(remote, buf); err != nil {
		t.Fatalf("remote read payload: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("remote got %q, want %q", buf, "hello")
	}
	// 应用的 FIN 必须已到达远端：下一次读取应为 EOF。
	if _, err := remote.Read(buf); err != io.EOF {
		t.Fatalf("remote read after app FIN = %v, want io.EOF", err)
	}

	// 远端应答并半关闭；中继必须把负载和 FIN 送回应用。
	if _, err := remote.Write([]byte("world")); err != nil {
		t.Fatalf("remote write: %v", err)
	}
	if err := remote.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("remote CloseWrite: %v", err)
	}
	if _, err := io.ReadFull(app, buf); err != nil {
		t.Fatalf("app read payload: %v", err)
	}
	if string(buf) != "world" {
		t.Fatalf("app got %q, want %q", buf, "world")
	}
	// 远端的 FIN 必须已到达应用。
	if _, err := app.Read(buf); err != io.EOF {
		t.Fatalf("app read after remote FIN = %v, want io.EOF", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return after both directions completed")
	}
	// 中继已关闭代理侧的两个 socket；应用/远端两端在上面看到了各自的 FIN，
	// 现在也已完全关闭。
	if !connClosed(t, app) {
		t.Error("app connection still open after relay completed")
	}
	if !connClosed(t, remote) {
		t.Error("remote connection still open after relay completed")
	}
}
