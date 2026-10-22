//go:build !headless

package tray

import (
	"testing"
	"time"
)

// TestRequestExitWakesEveryWaiter 守住广播语义：统计、更新与信号处理协程各自在 select
// 里等这个 channel，非阻塞 send 只能唤醒其中一个。
func TestRequestExitWakesEveryWaiter(t *testing.T) {
	s := NewShell()

	const waiters = 3
	woke := make(chan struct{}, waiters)
	for range waiters {
		go func() {
			<-s.closing
			woke <- struct{}{}
		}()
	}

	s.RequestExit()
	s.RequestExit() // 重复调用不能让 close 二次执行

	for range waiters {
		select {
		case <-woke:
		case <-time.After(time.Second):
			t.Fatal("requestExit did not wake every waiter")
		}
	}
}
