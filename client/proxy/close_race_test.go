package proxy

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
)

// TestSocks5CloseRacingStart 防护"刚启动 socks5 服务器就立即关闭"的场景：这会与
// txthinking/socks5 runnergroup 库内部的 accept 循环初始化产生竞争。GOMAXPROCS(1)
// 强制 Close 调用先于 Start 协程建立 accept 循环执行：没有同步机制的话，监听器会
// 泄漏（端口仍在接受连接），或 Shutdown 在 runnergroup.Done 的 <-g.done 上死锁。
//
// Close 会用一次真实的 SOCKS5 问候证明 accept 循环已运行，因此它要么在预算内
// 返回并已释放端口，要么带回错误——但绝不会为了等一个不会到来的信号而挂住：CI
// 上曾出现过后者，一个死锁把 windows-arm64 job 拖到 30 分钟超时才失败。
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
		closeErr := srv.Close()
		if closeErr != nil {
			// 预算内没等到 accept 循环时 Close 会跳过库的 Shutdown 而不是挂住。
			// 这条分支本身就是回归：曾经它会永久阻塞在 Shutdown 里。
			t.Fatalf("iteration #%d: Close: %v", i, closeErr)
		}

		// 给泄漏的 accept 循环一个运行的机会，然后验证端口确实已关闭。
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err == nil {
				c.Close() //nolint:errcheck
				t.Fatalf("iteration #%d: server still listening on %s after Close", i, addr)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
