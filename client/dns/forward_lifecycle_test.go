package dns

import (
	"net"
	"testing"
	"time"
)

// forwardLifecycleBudget 是"关闭/启动必须在预算内返回"的上限：把"永久挂住"
// 变成一次快速失败。正常路径远小于该值。
const forwardLifecycleBudget = 10 * time.Second

// freeUDPAddr 返回一个当前无人监听的 127.0.0.1 UDP 地址。
func freeUDPAddr(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// waitUDPAddrFree 等待 addr 可以重新绑定，报告它是否在预算内被释放。
func waitUDPAddrFree(addr string, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for {
		pc, err := net.ListenPacket("udp", addr)
		if err == nil {
			_ = pc.Close()
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestForwardServerShutdownBeforeStartReleasesPort 固定"Shutdown 先于 Start"这一
// 时序：迟到的 Start 必须关掉它刚绑定的 socket 并返回错误，而不是留下一个无人
// 引用的服务器永久占用端口。
//
// 旧形态下 Shutdown 只看到 dnsServer 尚未置位就返回 nil，随后 Start 绑定并
// 服务到进程结束；同一个进程里之后的 runner.Run 会在 prebindUDP 直接失败
// （53 端口被自己占用），整个客户端再也起不来。
func TestForwardServerShutdownBeforeStartReleasesPort(t *testing.T) {
	addr := freeUDPAddr(t)
	srv := NewForwardServer(addr, false)

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("Shutdown before Start: %v", err)
	}

	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()

	select {
	case err := <-startDone:
		if err == nil {
			t.Fatal("Start after Shutdown returned nil, want a closed error")
		}
	case <-time.After(forwardLifecycleBudget):
		t.Fatal("Start after Shutdown kept serving (UDP socket leaked, port held forever)")
	}

	if !waitUDPAddrFree(addr, forwardLifecycleBudget) {
		t.Fatalf("port %s is still held after Shutdown", addr)
	}
}

// TestForwardServerShutdownRacingStartReleasesPort 覆盖 Shutdown 与 Start 真正
// 并发的情形：miekg/dns 的 started 标志在绑定成功之后才置位，因此 Shutdown 落在
// 这个窗口里时它只会返回 "server not started"，什么都不做（旧形态因此泄漏
// socket）。这里不依赖调度顺序断言：无论谁先跑，端口都必须有界释放。
func TestForwardServerShutdownRacingStartReleasesPort(t *testing.T) {
	addr := freeUDPAddr(t)

	for i := range 20 {
		srv := NewForwardServer(addr, false)

		startDone := make(chan error, 1)
		go func() { startDone <- srv.Start() }()

		if err := srv.Shutdown(); err != nil {
			t.Fatalf("iteration #%d: Shutdown: %v", i, err)
		}

		select {
		case <-startDone:
		case <-time.After(forwardLifecycleBudget):
			t.Fatalf("iteration #%d: Start did not return after Shutdown", i)
		}

		if !waitUDPAddrFree(addr, forwardLifecycleBudget) {
			t.Fatalf("iteration #%d: port %s is still held after Shutdown", i, addr)
		}
	}
}

// TestForwardServerShutdownIsIdempotent 固定 Shutdown 的幂等性：重复调用不得
// 再次进入优雅关闭（第二次对已停止的 dns.Server 只会返回 "server not started"），
// 也不得 panic。
func TestForwardServerShutdownIsIdempotent(t *testing.T) {
	addr := freeUDPAddr(t)
	srv := NewForwardServer(addr, false)

	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()

	if !waitUDPAddrBound(addr) {
		t.Fatal("forward server never bound its port")
	}

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if err := srv.Shutdown(); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
	if !waitUDPAddrFree(addr, forwardLifecycleBudget) {
		t.Fatalf("port %s is still held after Shutdown", addr)
	}

	select {
	case <-startDone:
	case <-time.After(forwardLifecycleBudget):
		t.Fatal("Start did not return after Shutdown")
	}
}

// waitUDPAddrBound 等待 addr 上出现监听者，报告它是否在预算内上线。
func waitUDPAddrBound(addr string) bool {
	deadline := time.Now().Add(forwardLifecycleBudget)
	for {
		if !waitUDPAddrFree(addr, 0) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
