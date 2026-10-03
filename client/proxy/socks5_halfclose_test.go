package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// socksHalfCloseStub 是一个支持半关闭观测的 SOCKS5 服务端桩：完成无认证握手与
// CONNECT 应答后，先用 CONNECTED 通知测试已进入中继阶段，然后读到 EOF（对端
// CloseWrite）时向 sawEOF 投递一次，并继续反方向写回数据。
func socksHalfCloseStub(t *testing.T) (addr string, connected, sawEOF chan struct{}) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	connected = make(chan struct{}, 1)
	sawEOF = make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		// 握手：VER + NMETHODS + METHODS，协商为"无认证"。
		head := make([]byte, 2)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, int(head[1]))); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		// 请求：VER + CMD + RSV + ATYP，随后是地址与端口。只处理 IPv4 目标。
		req := make([]byte, 4)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		if req[3] != 0x01 {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
			return
		}
		// 成功应答：BND.ADDR = 0.0.0.0:0。
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}

		select {
		case connected <- struct{}{}:
		default:
		}

		// 读方向：客户端 CloseWrite 后这里必须立刻读到 EOF。旧实现（socks5.Client
		// 不支持 CloseWrite）会让本读取一直阻塞到 10s deadline 才返回。
		if _, err := io.Copy(io.Discard, conn); err == nil {
			select {
			case sawEOF <- struct{}{}:
			default:
			}
		}

		// 写方向：半关闭不得影响反方向，客户端仍应收到这份数据。
		_, _ = conn.Write([]byte("late"))
	}()

	return ln.Addr().String(), connected, sawEOF
}

// TestDialSOCKS5SupportsHalfClose 固定 http proxy 经本地 SOCKS5 入口建立的中继
// 支持半关闭。
//
// 背景：旧实现用 txthinking/socks5 的 *socks5.Client 作为 net.Conn，而该类型
// 没有 CloseWrite 方法，于是 route.go 的 copyHalfClose 里那句鸭子类型断言失败、
// 半关闭被静默跳过——与直连路径（dst 是 *net.TCPConn）行为不一致。本测试要求
// 客户端 CloseWrite 后服务端立刻看到 EOF，同时反方向数据仍可送达。
func TestDialSOCKS5SupportsHalfClose(t *testing.T) {
	stubAddr, connected, sawEOF := socksHalfCloseStub(t)

	srv, err := NewHTTPProxyServer(HTTPProxyOptions{
		ListenAddr: freeLoopbackAddr(t),
		SocksAddr:  stubAddr,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}

	conn, err := srv.dialSOCKS5("203.0.113.9:443")
	if err != nil {
		t.Fatalf("dialSOCKS5: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("stub never reached the relay stage")
	}

	// CloseWrite 必须被实现，否则半关闭无法传播。
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("%T does not implement CloseWrite", conn)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// 服务端必须在预算内看到 EOF，即半关闭真的传播出去了。
	select {
	case <-sawEOF:
	case <-time.After(3 * time.Second):
		t.Fatal("stub did not observe EOF after CloseWrite (half-close was not propagated)")
	}

	// 反方向仍须可用。
	got := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if !bytes.Equal(got, []byte("late")) {
		t.Errorf("reverse-direction data = %q, want %q", got, "late")
	}
}
