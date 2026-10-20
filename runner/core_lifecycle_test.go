package runner

import (
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// coreStopBudget 是单次 Stop 允许消耗的同步时间上限。正常路径只是"取消后台
// 任务 + 逐个关闭组件"，远小于该值；这个上限的唯一作用是把"重复 Stop 又走一遍
// 拆除流程"变成一次快速失败。
const coreStopBudget = time.Second

// listenerReleaseBudget 是 Stop 返回后等待监听端口释放的预算。
const listenerReleaseBudget = 10 * time.Second

// waitPortBindable 等待 127.0.0.1:port 可以重新绑定，报告它是否在预算内释放。
func waitPortBindable(port int) bool {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(listenerReleaseBudget)
	for {
		l, err := net.Listen("tcp", addr)
		if err == nil {
			_ = l.Close()
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCoreStopReleasesAllListeners 守住端口不泄漏：本地代理在 goroutine 里派发，核心可能
// 随即停止，若其 Close 早于 Start 的 Listen 就变成空操作，端口被永久占住。GOMAXPROCS(1) 放大该窗口。
func TestCoreStopReleasesAllListeners(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)

	for i := range 3 {
		cfg := testConfig()
		socksPort := freePort(t)
		httpPort := freePort(t)
		cfg.Local.SocksPort = socksPort
		cfg.Local.HTTPPort = httpPort

		core, err := Run(cfg)
		if err != nil {
			t.Fatalf("iteration #%d: Run: %v", i, err)
		}
		core.Stop()

		for name, port := range map[string]int{"socks5": socksPort, "http": httpPort} {
			if !waitPortBindable(port) {
				t.Fatalf("iteration #%d: %s port %d is still held after Stop", i, name, port)
			}
		}
	}
}

// TestCoreStopIsIdempotent 守住 Stop 幂等：托盘关闭与更新重启会对同一核心各调一次，
// 重复拆除会让关闭路径白等一次 accept 探测。
func TestCoreStopIsIdempotent(t *testing.T) {
	cfg := testConfig()
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	core.Stop()

	start := time.Now()
	core.Stop()
	if elapsed := time.Since(start); elapsed > coreStopBudget {
		t.Fatalf("second Stop took %s, want an immediate no-op", elapsed)
	}
}

// TestRunFailureReleasesBoundListeners 守住 Run 的统一清理路径：SOCKS5 已绑定而后续步骤
// 失败时端口必须随错误一起释放，新增资源或错误分支漏接会让重试启动一直失败。
func TestRunFailureReleasesBoundListeners(t *testing.T) {
	t.Run("http port conflict", func(t *testing.T) {
		_, httpPort := occupyTCPPort(t)
		socksPort := freePort(t)

		cfg := testConfig()
		cfg.Local.SocksPort = socksPort
		cfg.Local.HTTPPort = httpPort

		if core, err := Run(cfg); err == nil {
			core.Stop()
			t.Fatal("expected Run to fail when the http port is occupied")
		}
		if !waitPortBindable(socksPort) {
			t.Fatalf("socks5 port %d leaked after a failed Run", socksPort)
		}
	})

	t.Run("forward dns port conflict", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen packet: %v", err)
		}
		defer pc.Close() //nolint:errcheck

		addr := pc.LocalAddr().String()
		prev := forwardDNSListenAddr
		forwardDNSListenAddr = func() string { return addr }
		t.Cleanup(func() { forwardDNSListenAddr = prev })

		socksPort := freePort(t)
		cfg := testConfig()
		cfg.Local.SocksPort = socksPort
		cfg.Local.HTTPPort = 0
		cfg.Local.EnableForwardDNS = true

		if core, err := Run(cfg); err == nil {
			core.Stop()
			t.Fatal("expected Run to fail when the forward dns port is occupied")
		}
		if !waitPortBindable(socksPort) {
			t.Fatalf("socks5 port %d leaked after a failed Run", socksPort)
		}
	})
}
