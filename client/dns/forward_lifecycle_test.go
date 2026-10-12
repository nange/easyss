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

// heldSocket 返回服务器当前持有的监听 socket（未持有时为 nil）。
//
// 测试断言的是这个状态，而不是"同端口能否重新绑定"或"能不能从 socket 上读到
// 关闭错误"：绑定探测依赖平台语义（Windows 上 Go 不为监听 socket 设置
// SO_REUSEADDR，探测本身还会抢走端口，让服务器的绑定失败），而对同一 socket
// 并发读会与 serve 循环争抢 poll fd 的读锁、把测试挂死。
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

// TestForwardServerShutdownBeforeStartRefusesLateStart 固定"Shutdown 先于 Start"
// 这一时序：迟到的 Start 必须关掉它刚绑定的 socket 并返回 net.ErrClosed，绝不
// 登记任何监听 socket。
//
// 旧形态下 Shutdown 只看到 dnsServer 尚未置位就返回 nil，随后 Start 绑定并服务
// 到进程结束——同一个进程里之后的 runner.Run 会在 prebindUDP 直接失败（53 端口
// 被自己占着），整个客户端再也起不来。
func TestForwardServerShutdownBeforeStartRefusesLateStart(t *testing.T) {
	srv := NewForwardServer("127.0.0.1:0", false, nil)

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

// TestForwardServerShutdownRacingStartReleasesSocket 覆盖 Shutdown 与 Start 真正
// 并发的情形：miekg/dns 的 started 标志在绑定成功之后才置位，因此 Shutdown 落在
// 这个窗口里时它只会返回 "server not started"，什么都不做（旧形态因此泄漏
// socket）。这里不依赖调度顺序断言：无论谁先跑，Shutdown 返回后服务器都不得再
// 持有监听 socket。
func TestForwardServerShutdownRacingStartReleasesSocket(t *testing.T) {
	for i := range 20 {
		srv := NewForwardServer("127.0.0.1:0", false, nil)

		startDone := make(chan error, 1)
		go func() { startDone <- srv.Start() }()

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
	srv := NewForwardServer("127.0.0.1:0", false, nil)

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
	case <-startDone:
	case <-time.After(forwardLifecycleBudget):
		t.Fatal("Start did not return after Shutdown")
	}
}
