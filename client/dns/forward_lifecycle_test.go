package dns

import (
	"errors"
	"net"
	"testing"
	"time"
)

// forwardLifecycleBudget 是"关闭/启动必须在预算内返回"的上限：把"永久挂住"
// 变成一次快速失败。正常路径远小于该值。
const forwardLifecycleBudget = 10 * time.Second

// heldSocket 返回服务器当前持有的监听 socket（未持有时为 nil）。断言这个状态而不是
// 端口可重绑：Windows 上 Go 不设 SO_REUSEADDR，探测会抢走端口；并发读还会与 serve 循环争锁挂死测试。
func (s *ForwardServer) heldSocket() net.PacketConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pc
}

// waitForHeldSocket 等待 Start 登记好监听 socket。
func waitForHeldSocket(s *ForwardServer) bool {
	deadline := time.Now().Add(forwardLifecycleBudget)
	for {
		if s.heldSocket() != nil {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestForwardServerShutdownBeforeStartRefusesLateStart 守住该时序：迟到的 Start 必须关掉
// 刚绑定的 socket 并返回 net.ErrClosed，否则 53 端口被自己占着，runner.Run 再也绑不上。
func TestForwardServerShutdownBeforeStartRefusesLateStart(t *testing.T) {
	srv := NewForwardServer("127.0.0.1:0", false, alwaysTunActive)

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("Shutdown before Start: %v", err)
	}

	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()

	select {
	case err := <-startDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Start after Shutdown: got %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(forwardLifecycleBudget):
		t.Fatal("Start after Shutdown kept serving (a listening socket was leaked)")
	}

	if pc := srv.heldSocket(); pc != nil {
		t.Fatalf("Start after Shutdown registered a listening socket on %s", pc.LocalAddr())
	}
}

// TestForwardServerShutdownRacingStartReleasesSocket 覆盖 Shutdown 与 Start 并发：miekg/dns
// 的 started 标志在绑定成功后才置位，落在这个窗口的 Shutdown 只返回 "server not started"。
func TestForwardServerShutdownRacingStartReleasesSocket(t *testing.T) {
	for i := range 20 {
		srv := NewForwardServer("127.0.0.1:0", false, alwaysTunActive)

		startDone := make(chan struct{}, 1)
		go func() {
			_ = srv.Start()
			startDone <- struct{}{}
		}()

		if err := srv.Shutdown(); err != nil {
			t.Fatalf("iteration #%d: Shutdown: %v", i, err)
		}

		if pc := srv.heldSocket(); pc != nil {
			t.Fatalf("iteration #%d: server still holds a listening socket on %s after Shutdown",
				i, pc.LocalAddr())
		}

		select {
		case <-startDone:
		case <-time.After(forwardLifecycleBudget):
			t.Fatalf("iteration #%d: Start did not return after Shutdown", i)
		}
	}
}

// TestForwardServerShutdownIsIdempotent 固定 Shutdown 的幂等性：重复调用不得
// 再次进入优雅关闭（第二次对已停止的 dns.Server 只会返回 "server not started"），
// 也不得 panic；socket 必须在第一次调用后就已释放。
func TestForwardServerShutdownIsIdempotent(t *testing.T) {
	srv := NewForwardServer("127.0.0.1:0", false, alwaysTunActive)

	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()

	// 等 Start 登记 socket：此后它可能已经进入服务循环，也可能还没有——两种
	// 时序下 Shutdown 的契约相同（见 Shutdown 的说明）。
	if !waitForHeldSocket(srv) {
		select {
		case err := <-startDone:
			t.Fatalf("forward server never registered its socket: Start returned %v", err)
		case <-time.After(time.Second):
			t.Fatal("forward server never registered its socket")
		}
	}

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if pc := srv.heldSocket(); pc != nil {
		t.Fatalf("server still holds a listening socket on %s after Shutdown", pc.LocalAddr())
	}

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}

	select {
	case err := <-startDone:
		// 只固定"有界返回"：Shutdown 先到还是 serve 循环先起，决定 Start 返回 nil 还是 net.ErrClosed。
		_ = err
	case <-time.After(forwardLifecycleBudget):
		t.Fatal("Start did not return after Shutdown")
	}
}
