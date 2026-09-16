package handler

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
)

func TestOutboundTCPNetwork(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "domain",
			addr: "ipv6.msftncsi.com:80",
			want: "tcp",
		},
		{
			name: "ipv4 literal",
			addr: "192.0.2.1:80",
			want: "tcp4",
		},
		{
			name: "ipv6 literal",
			addr: net.JoinHostPort("2001:db8::1", "80"),
			want: "tcp6",
		},
		{
			name: "invalid hostport",
			addr: "missing-port",
			want: "tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outboundTCPNetwork(tt.addr); got != tt.want {
				t.Fatalf("outboundTCPNetwork(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

type stubConn struct {
	closed chan struct{}
	once   sync.Once
	remote net.Addr
}

func newStubConn(remote net.Addr) *stubConn {
	return &stubConn{closed: make(chan struct{}), remote: remote}
}

func (c *stubConn) Read(p []byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stubConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *stubConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *stubConn) LocalAddr() net.Addr { return &net.TCPAddr{} }

func (c *stubConn) RemoteAddr() net.Addr { return c.remote }

func (c *stubConn) SetDeadline(t time.Time) error { return nil }

func (c *stubConn) SetReadDeadline(t time.Time) error { return nil }

func (c *stubConn) SetWriteDeadline(t time.Time) error { return nil }

// isClosed 报告该 stub 是否已被调用 Close。
func (c *stubConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func TestTCPHandler_CancelReadOnIdleTimeout(t *testing.T) {
	h := newTCPHandler(150*time.Millisecond, 5*time.Second, nil)
	// 一个静默对端：stub 接受写入但从不产生数据，使用公网远端地址
	// 以便通过拨号后的 SSRF 防护。
	stub := newStubConn(&net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	h.dialContext = func(context.Context, string, string) (net.Conn, error) { return stub, nil }

	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		sharedconfig.EndpointTCP,
	)
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	dr, err := sk.NewReader(pr, crypto.DirS2C, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	s2cWriter, err := sk.NewWriter(io.Discard, crypto.DirS2C, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	s2c := shaper.New(s2cWriter, shaper.Config{})

	var cancelled atomic.Bool
	start := time.Now()
	err = h.Handle(context.Background(), dr, s2c, "8.8.8.8:53", func() { cancelled.Store(true) })
	if err == nil {
		t.Fatal("Handle should return an error on idle timeout")
	}
	if !cancelled.Load() {
		t.Fatal("cancelRead should be invoked when the relay terminates")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("Handle took too long to return")
	}
	_ = pw.Close()
}
