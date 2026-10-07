package runner

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/transport"
)

// fakeTransport 是只服务本文件的最小传输层：Open 记录请求并返回一条管道流的
// 一端，另一端留给测试扮演"隧道的对端"。
type fakeTransport struct {
	opened chan transport.OpenRequest

	mu   sync.Mutex
	peer net.Conn
}

func (f *fakeTransport) Open(_ context.Context, req transport.OpenRequest) (transport.Stream, error) {
	select {
	case f.opened <- req:
	default:
	}
	local, remote := net.Pipe()
	f.mu.Lock()
	f.peer = remote
	f.mu.Unlock()
	return pipeStream{Conn: local}, nil
}

func (f *fakeTransport) CloseIdle()                      {}
func (f *fakeTransport) Stats() transport.TransportStats { return transport.TransportStats{} }
func (f *fakeTransport) Close() error                    { return nil }

// peerConn 返回最近一次 Open 的对端（测试侧）。
func (f *fakeTransport) peerConn() net.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peer
}

// pipeStream 给 net.Pipe 补上 transport.Stream 需要的 CloseWrite。
type pipeStream struct{ net.Conn }

func (p pipeStream) CloseWrite() error { return p.Close() }

func newTestDERPHandler(t *testing.T) (*proxy.StreamHandler, *fakeTransport) {
	t.Helper()
	ft := &fakeTransport{opened: make(chan transport.OpenRequest, 4)}
	h := proxy.NewStreamHandler(ft, bytes.Repeat([]byte{0x7}, 32), shaper.Config{BatchWindowMS: 1}, 0)
	return h, ft
}

// TestDERPDialerCarriesTheConnectionOverTheTunnel 固定 DERP 拨号器的契约：它把
// tailcat 的连接变成一条经 easyss 隧道的流，目标原样进入握手；隧道断开时返回给
// tailcat 的连接也必须结束（DERP 客户端据此重连）。
func TestDERPDialerCarriesTheConnectionOverTheTunnel(t *testing.T) {
	const target = "derp.example.com:443"

	handler, ft := newTestDERPHandler(t)
	dial := newDERPDialer(handler, protocol.MethodAES256GCM)

	// DERP 客户端在拨号返回后立刻取消这次拨号的上下文（derphttp 在 dialNode 里
	// defer cancel），而这条流的寿命是整个 DERP 连接——拨号器必须不受影响。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := dial(ctx, "tcp", target)
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	select {
	case req := <-ft.opened:
		require.Equal(t, target, req.Target, "the DERP target must reach the handshake unchanged")
	case <-time.After(5 * time.Second):
		t.Fatal("the dialer never opened a tunnel stream")
	}

	peer := ft.peerConn()
	require.NotNil(t, peer)

	// 隧道那一侧先收到引导记录：这证明这条连接真的被送进了 easyss 协议。
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := peer.Read(make([]byte, 1))
	require.NoError(t, err, "the tunnel side never received the bootstrap record")
	require.Equal(t, 1, n)

	// 隧道断开（服务端关闭 / 核心停止）→ 交给 tailcat 的连接必须结束。
	require.NoError(t, peer.Close())
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err, "the DERP connection must end when the tunnel does")
}

// TestDERPDialerRejectsNonTCP 固定网络名门控：DERP 是 TCP 上的 HTTPS，UDP/ICMP
// 不应该被悄悄送进这条路径。
func TestDERPDialerRejectsNonTCP(t *testing.T) {
	handler, _ := newTestDERPHandler(t)
	dial := newDERPDialer(handler, protocol.MethodAES256GCM)

	for _, network := range []string{"udp", "udp4", "icmp"} {
		if _, err := dial(context.Background(), network, "derp.example.com:443"); err == nil {
			t.Errorf("dial(%q) succeeded, want an error", network)
		}
	}
}
