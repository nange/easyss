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

// TestCoreStopReleasesAllListeners 固定"核心停止后所有本地监听端口都被释放"。
//
// 本地代理服务器都在 goroutine 中被派发（见 Run），而核心可能随即被停止——
// 托盘切换服务器、mobile.Stop、测试都是这条路径。GOMAXPROCS(1) 让"Close 先于
// Start 的 Listen 生效"这一窗口尽可能暴露：旧形态下 HTTP 入口的 Close 会因为
// 自己还没有登记监听器而变成空操作，迟到的 Start 于是永久占住端口，下一次
// runner.Run 会在 prebindTCP 直接失败。
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

// TestCoreStopIsIdempotent 固定 Stop 的幂等性。托盘的关闭流程与更新重启路径
// 会对同一个核心各调一次 Stop（见 cmd/easyss 的 closeService/restartService），
// 旧形态下第二次会重新拆除一遍：Socks5Server.Close 在已关闭的监听地址上做
// accept 探测，白等 acceptProbeTimeout 并留下一个 30 秒的后台补关闭 goroutine。
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
