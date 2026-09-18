package proxy

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
)

// closeSyncBudget 是单次 Close 允许消耗的同步时间上限。正常路径只是"一次探测 +
// 一次 runnergroup.Done"，远小于该值；这个上限的唯一作用是把"永久挂住"变成一次
// 快速失败（旧形态会把整个 job 拖到 go test 的 30 分钟超时）。
const closeSyncBudget = 15 * time.Second

// closeFastReleaseBudget 是同步 Shutdown 成功后等待监听器释放的预算：库的 Done
// 在返回前已经调过 runner 的 Stop（关掉 TCP 监听），所以端口应当立刻不可用。
const closeFastReleaseBudget = 2 * time.Second

// closeDeferredReleaseBudget 是补关闭路径上等待监听器释放的预算。Close 返回
// errAcceptNotReady 时 accept 循环还没上线，端口要等它就绪后由后台补关闭释放
// （见 Socks5Server.shutdown），因此这里覆盖 acceptShutdownGrace 并留出调度余量。
const closeDeferredReleaseBudget = acceptShutdownGrace + 10*time.Second

// TestSocks5CloseRacingStart 防护"刚启动 socks5 服务器就立即关闭"的场景：这会与
// txthinking/socks5 runnergroup 库内部的 accept 循环初始化产生竞争。GOMAXPROCS(1)
// 强制 Close 调用先于 Start 协程建立 accept 循环执行：没有同步机制的话，监听器会
// 泄漏（端口仍在接受连接），或 Shutdown 在 runnergroup.Done 的 <-g.done 上死锁。
//
// 这里断言的两条不变量都与调度快慢无关：
//  1. Close 必须在有界时间内返回——旧形态是在 <-g.done 上永久阻塞。
//  2. 监听器必须在预算内释放——同步 Shutdown 成功时立刻成立，探测没答上时由
//     后台补关闭在 accept 循环就绪后完成。
//
// 3s 的同步探测预算在超载 runner 上曾被调度延迟耗尽，因此"探测没答上"本身不再
// 是失败：只有"Close 挂住"和"端口一直没释放"才是。
func TestSocks5CloseRacingStart(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)

	for i := range 5 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := l.Addr().String()
		l.Close() //nolint:errcheck

		h := newTestStreamHandler(&mockTransport{})
		srv, err := NewSocks5Server(Socks5Options{
			ListenAddr: addr,
			Handler:    h,
			Method:     protocol.MethodAES256GCM,
			Timeouts: config.Timeouts{
				Base:       30 * time.Second,
				Dial:       10 * time.Second,
				StreamIdle: 30 * time.Second,
			},
		})
		if err != nil {
			t.Fatalf("NewSocks5Server #%d: %v", i, err)
		}
		srv.MarkStarted()
		go srv.Start() //nolint:errcheck

		// Close 在预算内必须返回：拿不到返回值就是死锁回归。
		closeDone := make(chan error, 1)
		go func() { closeDone <- srv.Close() }()
		var closeErr error
		select {
		case closeErr = <-closeDone:
		case <-time.After(closeSyncBudget):
			t.Fatalf("iteration #%d: Close did not return within %s (deadlock regression)", i, closeSyncBudget)
		}
		// errAcceptNotReady 是允许的结果：accept 循环迟到时补关闭交给了后台，
		// 监听器要等 accept 循环就绪后才会被释放。其余错误才是回归。
		if closeErr != nil && !errors.Is(closeErr, errAcceptNotReady) {
			t.Fatalf("iteration #%d: Close: %v", i, closeErr)
		}
		budget := closeFastReleaseBudget
		if closeErr != nil {
			budget = closeDeferredReleaseBudget
		}
		if err := waitListenerGone(addr, budget); err != nil {
			t.Fatalf("iteration #%d: %v", i, err)
		}
	}
}

// waitListenerGone 等待 addr 彻底不再接受 TCP 连接，报告监听器是否在预算内释放。
// accept 循环迟到时端口会先绑定、后由补关闭释放，因此调用方按路径给出不同预算：
// 同步路径应当立刻释放，补关闭路径则要等 accept 循环上线。
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

// TestSocks5DeferredShutdownClosesListener 覆盖 Close 的补关闭路径：同步探测没能
// 确认 accept 循环时 Close 返回 errAcceptNotReady 并立即返回，此后 accept 循环才
// 真正上线——后台补关闭必须在它上线后关掉监听器，否则那个迟到的监听器会被永久
// 遗弃（端口一直有人在服务）。
//
// 用"Close 先于 Start"稳定地构造这个迟到：同步探测必然失败，而 Start 随后启动的
// accept 循环会让后台那次探测成功，从而补做库的 Shutdown。
func TestSocks5DeferredShutdownClosesListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close() //nolint:errcheck

	srv, err := NewSocks5Server(Socks5Options{
		ListenAddr: addr,
		Handler:    newTestStreamHandler(&mockTransport{}),
		Method:     protocol.MethodAES256GCM,
		Timeouts: config.Timeouts{
			Base:       30 * time.Second,
			Dial:       10 * time.Second,
			StreamIdle: 30 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	srv.MarkStarted()

	start := time.Now()
	closeErr := srv.Close()
	if !errors.Is(closeErr, errAcceptNotReady) {
		t.Fatalf("Close before Start: got %v, want errAcceptNotReady", closeErr)
	}
	// 补关闭不能把同步路径变成无限等待：Close 只允许消耗同步探测预算。
	if elapsed := time.Since(start); elapsed > closeSyncBudget {
		t.Fatalf("Close took %s, want <= %s", elapsed, closeSyncBudget)
	}

	// 服务器现在才真正起来：accept 循环一就绪，补关闭就该把它关掉。
	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()
	select {
	case <-startDone:
	case <-time.After(closeDeferredReleaseBudget):
		t.Fatalf("deferred shutdown did not stop the server within %s", closeDeferredReleaseBudget)
	}
	if err := waitListenerGone(addr, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}
