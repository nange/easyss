package nextproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type socks5ConnRequest struct {
	atyp    byte
	host    string
	port    int
	user    string
	pass    string
	hasAuth bool
}

// startSocks5HandshakeStub 启动最小的 SOCKS5 服务端桩：完成握手与 CONNECT 应答并记录目标与凭据，
// 协商后保持连接打开（与真实代理一致），拨号返回的连接因此可直接读写。
func startSocks5HandshakeStub(t *testing.T, wantAuth bool) (string, <-chan socks5ConnRequest) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	got := make(chan socks5ConnRequest, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				req, err := socks5ServeHandshake(c, wantAuth)
				if err != nil {
					return
				}
				got <- req
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), got
}

func socks5ServeHandshake(c net.Conn, wantAuth bool) (socks5ConnRequest, error) {
	var req socks5ConnRequest

	// 握手：VER + NMETHODS + METHODS。
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return req, err
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return req, err
	}

	if wantAuth {
		if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
			return req, err
		}
		// RFC 1929：VER + ULEN + UNAME + PLEN + PASSWD。
		ver := make([]byte, 2)
		if _, err := io.ReadFull(c, ver); err != nil {
			return req, err
		}
		if ver[0] != 0x01 {
			return req, errors.New("bad auth version")
		}
		uname := make([]byte, int(ver[1]))
		if _, err := io.ReadFull(c, uname); err != nil {
			return req, err
		}
		var plen [1]byte
		if _, err := io.ReadFull(c, plen[:]); err != nil {
			return req, err
		}
		passwd := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(c, passwd); err != nil {
			return req, err
		}
		req.user, req.pass, req.hasAuth = string(uname), string(passwd), true
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return req, err
		}
	} else {
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
			return req, err
		}
	}

	// 请求：VER + CMD + RSV + ATYP + ADDR + PORT。
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return req, err
	}
	req.atyp = hdr[3]
	switch hdr[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c, addr); err != nil {
			return req, err
		}
		req.host = net.IP(addr).String()
	case 0x03:
		var ln [1]byte
		if _, err := io.ReadFull(c, ln[:]); err != nil {
			return req, err
		}
		addr := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(c, addr); err != nil {
			return req, err
		}
		req.host = string(addr)
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(c, addr); err != nil {
			return req, err
		}
		req.host = net.IP(addr).String()
	default:
		return req, errors.New("unexpected atyp")
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return req, err
	}
	req.port = int(binary.BigEndian.Uint16(port[:]))

	// 成功应答：BND.ADDR = 0.0.0.0:0。
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return req, err
	}
	return req, nil
}

// TestDialContextThroughStub 固定目标以域名（ATYP=0x03）交给代理、不做本地解析。
func TestDialContextThroughStub(t *testing.T) {
	addr, got := startSocks5HandshakeStub(t, false)

	np, err := New("socks5://"+addr, false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	np.SetDialTimeout(5 * time.Second)

	conn, err := np.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	req := <-got
	if req.atyp != 0x03 {
		t.Errorf("atyp = %#x, want 0x03 (domain)", req.atyp)
	}
	if req.host != "example.com" {
		t.Errorf("host = %q, want example.com", req.host)
	}
	if req.port != 443 {
		t.Errorf("port = %d, want 443", req.port)
	}
	if req.hasAuth {
		t.Error("unexpected username/password negotiation")
	}
}

// TestDialContextSendsCredentials 固定 URL 中的凭据以 RFC 1929 用户名/密码方式协商。
func TestDialContextSendsCredentials(t *testing.T) {
	addr, got := startSocks5HandshakeStub(t, true)

	np, err := New("socks5://alice:s3cr3t@"+addr, false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	np.SetDialTimeout(5 * time.Second)

	conn, err := np.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	req := <-got
	if !req.hasAuth || req.user != "alice" || req.pass != "s3cr3t" {
		t.Errorf("auth = %v (%q/%q), want alice/s3cr3t", req.hasAuth, req.user, req.pass)
	}
}

// TestDialContextHonorsContextCancellation 固定 ctx 取消能中止拨号，但只断言"被及时中止"而不核对错误类型：
// x/net/proxy 只在拨通上游代理时检查 ctx，SOCKS5 握手读写不带 deadline，到期常表现为 i/o timeout，
// 真正的上界来自 SetDialTimeout 派生的 net.Dialer.Timeout。
func TestDialContextHonorsContextCancellation(t *testing.T) {
	// 一个只接受连接、不对握手作任何应答的服务端：拨号只能靠 ctx 结束。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// 已接受的连接记在 sync.Map 里：accept goroutine 与测试 goroutine 并发，普通切片会引入数据竞争。
	var accepted sync.Map
	t.Cleanup(func() {
		accepted.Range(func(_, v any) bool {
			if c, ok := v.(net.Conn); ok {
				_ = c.Close()
			}
			return true
		})
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Store(conn, conn)
		}
	}()

	np, err := New("socks5://"+ln.Addr().String(), false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := np.DialContext(ctx, "tcp", "example.com:443")
	if err == nil {
		conn.Close() //nolint:errcheck
		t.Fatal("expected an error from a black-hole proxy, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Logf("dial error (context not wrapped, but dial was still aborted): %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("dial took %v, expected it to be aborted by ctx", elapsed)
	}
}

// TestDialContextFailsWhenProxyRefuses 固定上游代理不可达时返回错误而不是挂起，且错误里带目标地址。
func TestDialContextFailsWhenProxyRefuses(t *testing.T) {
	// 先占一个端口再释放，得到一个几乎肯定无人监听的地址。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	np, err := New("socks5://"+addr, false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	np.SetDialTimeout(2 * time.Second)

	conn, err := np.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		conn.Close() //nolint:errcheck
		t.Fatal("expected an error when the proxy is unreachable")
	}
	if !strings.Contains(err.Error(), "example.com:443") {
		t.Errorf("error %q should mention the target address", err)
	}
}
