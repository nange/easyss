package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/transport"
)

// blockingStream 是一个 transport.Stream，其 Read 会阻塞直到 Close 被调用，
// 模拟一个从不应答的服务器（例如静默丢弃查询的上游 DNS 服务器）。
// Write 总是成功，因此 bootstrap 握手可以完成。
type blockingStream struct {
	mu     sync.Mutex
	closed bool
	wake   chan struct{}
}

func newBlockingStream() *blockingStream {
	return &blockingStream{wake: make(chan struct{})}
}

func (s *blockingStream) Read(p []byte) (int, error) {
	<-s.wake
	return 0, net.ErrClosed
}

func (s *blockingStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *blockingStream) CloseWrite() error { return nil }

func (s *blockingStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.wake)
	}
	return nil
}

func (s *blockingStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

var _ transport.Stream = (*blockingStream)(nil)

const testDNSRespTimeout = 200 * time.Millisecond

// newTimeoutTestServer 构建一个 Socks5Server：其代理 DNS 交换使用 testDNSRespTimeout
// 超时，其传输层提供给定的流。
func newTimeoutTestServer(t *testing.T, streams []transport.Stream) *Socks5Server {
	t.Helper()
	h := newTestStreamHandler(&mockTransport{streams: streams})
	srv, err := NewSocks5Server(Socks5Options{
		ListenAddr: "127.0.0.1:0",
		Handler:    h,
		Method:     protocol.MethodAES256GCM,
		Timeouts: config.Timeouts{
			Base:       30 * time.Second,
			Dial:       10 * time.Second,
			StreamIdle: 30 * time.Second,
			DNSResp:    testDNSRespTimeout,
		},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	return srv
}

func (s *Socks5Server) hasExchange(key string) bool {
	s.udpMu.RLock()
	defer s.udpMu.RUnlock()
	_, ok := s.udpExch[key]
	return ok
}

// waitExchangeReaped 轮询直到该键从 s.udpExch 中消失（由 receiveLoop 的 defer 移除）
// 或截止时间到期。
func waitExchangeReaped(t *testing.T, s *Socks5Server, key string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for s.hasExchange(key) {
		if time.Now().After(deadline) {
			t.Fatalf("exchange %q not reaped within deadline", key)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestUDPExchangeDNSResponseTimeout 验证当 dnsRespTimeout 到期后，没有服务器响应的
// 代理 DNS 交换会被关闭（流被关闭、键被移除），这样静默的上游 DNS 服务器就无法堆积
// HTTP/2 流和 receiveLoop 协程。
func TestUDPExchangeDNSResponseTimeout(t *testing.T) {
	bs := newBlockingStream()
	srv := newTimeoutTestServer(t, []transport.Stream{bs})

	key := "127.0.0.1:12345_8.8.8.8:53"
	ue, created, err := srv.getOrCreateUDPExchange(context.Background(), key, "8.8.8.8:53", []byte("dns query payload"))
	if err != nil {
		t.Fatalf("getOrCreateUDPExchange: %v", err)
	}
	if !created {
		t.Fatal("expected exchange to be created")
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	go srv.receiveLoop(ue, nil, clientAddr, "8.8.8.8:53", key, srv.dnsRespTimeout)

	if !srv.hasExchange(key) {
		t.Fatal("expected exchange to be registered before the timeout")
	}

	waitExchangeReaped(t, srv, key)

	if !bs.isClosed() {
		t.Error("expected exchange stream to be closed after response timeout")
	}
}

// TestUDPExchangeNoTimeoutWhenDisabled 验证 respTimeout=0（非 DNS 的 UDP 路径）时，
// 即使超过 dnsRespTimeout，交换也不会被处理：长时间的下行静默绝不能终止常规 UDP 会话。
func TestUDPExchangeNoTimeoutWhenDisabled(t *testing.T) {
	bs := newBlockingStream()
	srv := newTimeoutTestServer(t, []transport.Stream{bs})

	key := "127.0.0.1:12345_8.8.8.8:443"
	ue, created, err := srv.getOrCreateUDPExchange(context.Background(), key, "8.8.8.8:443", []byte("udp payload"))
	if err != nil {
		t.Fatalf("getOrCreateUDPExchange: %v", err)
	}
	if !created {
		t.Fatal("expected exchange to be created")
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	go srv.receiveLoop(ue, nil, clientAddr, "8.8.8.8:443", key, 0)

	time.Sleep(testDNSRespTimeout * 2)
	if !srv.hasExchange(key) {
		t.Fatal("exchange must not be reaped when the response timeout is disabled")
	}
	if bs.isClosed() {
		t.Error("stream must not be closed when the response timeout is disabled")
	}

	// 收尾：关闭交换使阻塞的 receiveLoop 退出并清理键，然后等待协程结束。
	ue.Close() //nolint:errcheck
	waitExchangeReaped(t, srv, key)
}
