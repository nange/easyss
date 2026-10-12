package proxy

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
)

// newDirectOnlyServer 构造一个"所有目标都直连"的 Socks5Server，用于覆盖
// VPN 对端面所依赖的那条路径（见 router.NewDirectOnly）。
func newDirectOnlyServer(t *testing.T) *Socks5Server {
	t.Helper()
	srv, err := NewSocks5Server(Socks5Options{
		Router:   router.NewDirectOnly(),
		Timeouts: config.Timeouts{Dial: 2 * time.Second, UDPIdle: 5 * time.Second, StreamIdle: 2 * time.Second},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	return srv
}

// echoOnce 对 target 做一次 SOCKS5 CONNECT 往返，返回收到的回显。
func echoOnce(t *testing.T, socksAddr, target, payload string) string {
	t.Helper()
	conn := socks5HandshakeConnectRaw(t, socksAddr, target)
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	return string(buf)
}

// TestServeUsesCallerListener 固定 Serve 的所有权契约：它在调用方提供的 listener
// 上服务，并且**不**持有它。
//
// 这是 VPN 对端面的前提——对端面用的监听器来自 tailcat 的 gVisor netstack，
// 那种监听器不属于宿主，也绝不能由 Socks5Server.Close 关闭（关闭它会连带拆掉
// 隧道的服务端口）。因此：Close 之后调用方的 listener 必须仍然可用；而调用方
// 关闭 listener 之后，Serve 必须正常返回而不是报错。
func TestServeUsesCallerListener(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()

	srv := newDirectOnlyServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	socksAddr := ln.Addr().String()

	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ln) }()

	// 第一次往返：证明 Serve 真的在服务（不是"起了 goroutine 但没 accept"）。
	if got := echoOnce(t, socksAddr, echoAddr, "before-close"); got != "before-close" {
		t.Fatalf("echo = %q, want before-close", got)
	}

	// Close 只收自己创建的东西：传入的 listener 不属于它。
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-serveDone:
		t.Fatalf("Serve returned after Close even though the caller's listener is still open: %v", err)
	default:
	}

	// 第二次往返：listener 仍然可用，说明它没有被 Close 关掉。
	if got := echoOnce(t, socksAddr, echoAddr, "after-close"); got != "after-close" {
		t.Fatalf("echo after Close = %q, want after-close", got)
	}

	// 调用方关掉 listener，Serve 才返回，且 net.ErrClosed 不应被当成错误抛出。
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil after the listener was closed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the caller closed the listener")
	}
}

// TestNewDirectOnlyRoutesEverythingDirectly 固定对端面所用路由器的语义：任何目标
// （域名、IPv4、IPv6、内网地址）都判为直连，且不会被 IPv6 策略门拦下。
//
// 这条不变量是"对端面只可能拨本机 loopback"的实现基础：对端面不做任何分流判定，
// 唯一的门槛是拨号器自己。
func TestNewDirectOnlyRoutesEverythingDirectly(t *testing.T) {
	rt := router.NewDirectOnly()
	for _, host := range []string{
		"example.com", "127.0.0.1", "::1", "2001:db8::1", "10.0.0.1", "192.168.1.1", "localhost",
	} {
		cls := rt.ClassifyHost(host)
		if cls.IPV6Rejected {
			t.Errorf("ClassifyHost(%q) was rejected by the IPv6 gate; the peer face must be able to reach ::1", host)
		}
		if cls.Rule != router.HostRuleDirect {
			t.Errorf("ClassifyHost(%q).Rule = %v, want direct", host, cls.Rule)
		}
	}
	if got := rt.ProxyRule(); got != router.ProxyRuleDirect {
		t.Errorf("ProxyRule() = %v, want direct", got)
	}
}
