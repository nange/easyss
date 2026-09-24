package proxy

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/txthinking/socks5"
)

// recordingDialer 包装一个普通的 UDP dialer：记录每个拨号得到的连接，并延迟每次拨号，
// 使并发的数据报处理器在直连 UDP 中继路径的（查 map -> 拨号 -> 插入）窗口内重叠。
type recordingDialer struct {
	mu    sync.Mutex
	conns []net.Conn
	delay time.Duration
}

func (d *recordingDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	time.Sleep(d.delay)
	c, err := net.Dial(network, addr)
	if err == nil {
		d.mu.Lock()
		d.conns = append(d.conns, c)
		d.mu.Unlock()
	}
	return c, err
}

func (d *recordingDialer) dialed() []net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]net.Conn(nil), d.conns...)
}

func newDirectUDPTestServer(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) *Socks5Server {
	t.Helper()
	h := newTestStreamHandler(&mockTransport{})
	srv, err := NewSocks5Server(Socks5Options{
		ListenAddr: "127.0.0.1:0",
		Handler:    h,
		Method:     protocol.MethodAES256GCM,
		Timeouts: config.Timeouts{
			Base:       30 * time.Second,
			Dial:       10 * time.Second,
			StreamIdle: 30 * time.Second,
		},
		DirectDialContext: dial,
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	return srv
}

// startSilentRemoteUDP 启动一个本地 UDP"远端"，它静默丢弃所有数据报，这样中继的读循环
// 永远不会收到数据，也永远不会调用 sendToClient（后者需要一个带 UDPConn 的真实
// socks5.Server）。
func startSilentRemoteUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen remote udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() }) //nolint:errcheck
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

func directTestDatagram(dst string, data byte) *socks5.Datagram {
	host, portStr, _ := net.SplitHostPort(dst)
	port, _ := strconv.Atoi(portStr)
	return socks5.NewDatagram(socks5.ATYPIPv4, net.ParseIP(host).To4(), []byte{byte(port >> 8), byte(port)}, []byte{data})
}

// TestDirectUDPRelayConcurrentDial 验证针对同一个（client, target）键并发处理的两个
// 数据报只会创建一个直连 UDP 会话。修复前的代码在查 map 与插入之间存在竞争，导致两个
// 处理器都拨号：一个 socket 成为孤儿（连同其读协程一起泄漏，最多持续到读空闲截止时间），
// 而孤儿的清理随后删除了仍在使用的 map 条目，使长连接流（QUIC、游戏、VoIP）每约
// udpIdleTimeout（默认 60s）就换一个新 socket。
func TestDirectUDPRelayConcurrentDial(t *testing.T) {
	dst := startSilentRemoteUDP(t)

	d := &recordingDialer{delay: 80 * time.Millisecond}
	srv := newDirectUDPTestServer(t, d.dial)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43210}
	key := "direct_" + clientAddr.String() + "_" + dst

	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if err := srv.directUDPRelay(&socks5.Server{}, clientAddr, directTestDatagram(dst, 1), dst); err != nil {
				t.Errorf("directUDPRelay: %v", err)
			}
		})
	}
	wg.Wait()

	if got := len(d.dialed()); got != 1 {
		t.Fatalf("dialed %d UDP sockets for one session, want 1 (duplicate dial orphans a socket and its read goroutine)", got)
	}

	dc, ok := srv.udp.directFor(key)
	if !ok || dc == nil {
		t.Fatal("direct UDP session not registered in the map")
	}
}

// TestDirectUDPRelayStaleReadLoopKeepsLiveEntry 验证读循环为一个不再属于自己的 socket
// 退出时，绝不能删除活跃会话的 map 条目。修复前，循环的 defer 会盲目删除条目，
// 导致会话被静默丢弃，而其 socket 却继续残留。
func TestDirectUDPRelayStaleReadLoopKeepsLiveEntry(t *testing.T) {
	dst := startSilentRemoteUDP(t)

	d := &recordingDialer{delay: 0}
	srv := newDirectUDPTestServer(t, d.dial)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43211}
	key := "direct_" + clientAddr.String() + "_" + dst

	if err := srv.directUDPRelay(&socks5.Server{}, clientAddr, directTestDatagram(dst, 1), dst); err != nil {
		t.Fatalf("directUDPRelay: %v", err)
	}
	live, ok := srv.udp.directFor(key)
	if !ok || live == nil {
		t.Fatal("live session missing before stale loop test")
	}

	// 一个同键但不属于 map 条目的过期 socket（这正是重复拨号竞争产生的结果）：
	// 它的读循环必须退出，且不得驱逐活跃会话。
	staleConn, err := srv.directDialContext(context.Background(), "udp", dst)
	if err != nil {
		t.Fatalf("dial stale conn: %v", err)
	}
	stale := &directUDPConn{conn: staleConn}
	go srv.directUDPReadLoop(&socks5.Server{}, clientAddr, dst, key, stale)
	_ = staleConn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, ok := srv.udp.directFor(key)
		if !ok {
			t.Fatal("stale read loop deleted the live session's map entry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // 等待任何迟到的删除操作落定
	_, ok = srv.udp.directFor(key)
	if !ok {
		t.Fatal("live session's map entry disappeared after stale loop exit")
	}

	// 阳性对照：所属读循环退出时仍必须清理自己的条目。
	_ = live.conn.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, ok = srv.udp.directFor(key)
		if !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned read loop did not delete its map entry on exit")
}
