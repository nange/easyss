package proxy

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

// closeSyncBudget 是单次 Close 允许消耗的同步时间上限。现在的实现只是"关几个
// socket"，远小于该值；这个上限的唯一作用是把"永久挂住"变成一次快速失败。
const closeSyncBudget = 15 * time.Second

// closeFastReleaseBudget 是 Close 返回后等待监听器释放的预算。Close 直接关闭自己
// 持有的监听器，因此端口应当立刻不可用。
const closeFastReleaseBudget = 2 * time.Second

// TestSocks5CloseRacingStart 守住 Close 与 Start 的竞争窗口（由 Socks5Server.listenerMu
// 裁决）：Close 必须在有界时间内返回，且迟到的 Start 必须自行释放监听器，否则端口被永久占住。
func TestSocks5CloseRacingStart(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)

	for i := range 5 {
		addr := reserveLoopbackAddr(t)

		srv := newTestSocks5Server(t, addr)
		go srv.Start() //nolint:errcheck

		// Close 在预算内必须返回：拿不到返回值就是回归。
		closeDone := make(chan error, 1)
		go func() { closeDone <- srv.Close() }()
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("iteration #%d: Close: %v", i, err)
			}
		case <-time.After(closeSyncBudget):
			t.Fatalf("iteration #%d: Close did not return within %s", i, closeSyncBudget)
		}

		if err := waitListenerGone(addr, closeFastReleaseBudget); err != nil {
			t.Fatalf("iteration #%d: %v", i, err)
		}
	}
}

// TestSocks5CloseBeforeStartReleasesListener 守住"Close 先于 Start"：迟到的 Start 必须释放
// 自己创建的监听器。runner 在 goroutine 里派发 Start，核心可能随即被停，端口泄漏会让重启失败。
func TestSocks5CloseBeforeStartReleasesListener(t *testing.T) {
	addr := reserveLoopbackAddr(t)

	srv := newTestSocks5Server(t, addr)

	// Close 先于 Start：没有任何监听器需要释放，必须安全且快速。
	start := time.Now()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
	if elapsed := time.Since(start); elapsed > closeSyncBudget {
		t.Fatalf("Close took %s, want <= %s", elapsed, closeSyncBudget)
	}

	// 服务器现在才真正起来：它必须自己退出并把监听器释放掉。
	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start after Close: %v", err)
		}
	case <-time.After(closeSyncBudget):
		t.Fatal("Start after Close kept serving (listener leaked, port held forever)")
	}

	if err := waitListenerGone(addr, closeFastReleaseBudget); err != nil {
		t.Fatal(err)
	}
}

// waitListenerGone 等待 addr 彻底不再接受 TCP 连接，报告监听器是否在预算内释放。
func waitListenerGone(addr string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return nil
		}
		c.Close() //nolint:errcheck
		if !time.Now().Before(deadline) {
			return fmt.Errorf("socks5 listener on %s is still up after %s", addr, budget)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// reserveLoopbackAddr 返回一个刚被释放的回环地址，供"先探测再绑定"的测试使用。
func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close reserved listener: %v", err)
	}
	return addr
}
