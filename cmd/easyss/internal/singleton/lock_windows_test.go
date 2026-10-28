//go:build windows && !headless

package singleton

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// handoffHelperEnv 让同一个测试二进制以"旧实例"身份重入：持锁、等交接事件、退出。
const handoffHelperEnv = "EASYSS_SINGLETON_HANDOFF_HELPER"

// 这些用例共享进程级的命名互斥量与事件，必须串行：并行会互相抢锁或消费对方的信号。
func TestTryAcquireRejectsTheSecondInstance(t *testing.T) {
	Release()
	require.NoError(t, TryAcquire())
	t.Cleanup(Release)

	require.ErrorIs(t, TryAcquire(), ErrAnotherInstance, "同一会话的第二个实例必须被拒绝")
}

func TestReleaseLetsAnotherInstanceIn(t *testing.T) {
	Release()
	require.NoError(t, TryAcquire())

	Release()

	require.NoError(t, TryAcquire(), "释放后新实例必须能拿到锁")
	t.Cleanup(Release)
}

// TestRequestRestartWakesTheRunningInstance 钉住交接协议：旧实例阻塞在
// WaitRestartRequest 上，新实例 RequestRestart 之后它必须被唤醒，否则提权重启会一直
// 等到超时、最终两个实例都没有起来。
func TestRequestRestartWakesTheRunningInstance(t *testing.T) {
	// 先建出命名事件并持有句柄：两侧都是"打开同名对象"，对象不能在等待方打开前消失。
	holder, err := createRestartEvent()
	require.NoError(t, err)
	t.Cleanup(func() { _ = windows.CloseHandle(holder) })

	woke := make(chan bool, 1)
	go func() { woke <- WaitRestartRequest() }()

	require.NoError(t, RequestRestart())

	select {
	case ok := <-woke:
		require.True(t, ok, "等待方必须被唤醒")
	case <-time.After(5 * time.Second):
		t.Fatal("WaitRestartRequest was not woken up by RequestRestart")
	}
}

// TestAcquireAfterRestartWithoutAnotherInstance 固定"没有旧实例时直接拿到锁"：用户手动
// 双击或上一次交接已完成后，新进程不该为此空等一个超时。
func TestAcquireAfterRestartWithoutAnotherInstance(t *testing.T) {
	Release()
	require.NoError(t, AcquireAfterRestart(time.Second))
	t.Cleanup(Release)
}

// TestHandoffTakesTheLockFromAnotherProcess 跨进程跑一遍完整交接：命名对象在会话命名空间里
// 必须对另一个进程可见，否则提权重启后新进程会以为没有旧实例（两个实例并存）或永远拿不到锁。
func TestHandoffTakesTheLockFromAnotherProcess(t *testing.T) {
	if os.Getenv(handoffHelperEnv) == "1" {
		// 旧实例：持锁 → 阻塞等交接 → 直接退出（生产路径由托盘退出流程做同样的收尾）。
		if err := TryAcquire(); err != nil {
			os.Exit(3)
		}
		if !WaitRestartRequest() {
			os.Exit(4)
		}
		os.Exit(0)
	}

	Release()

	child := exec.Command(os.Args[0], "-test.run=TestHandoffTakesTheLockFromAnotherProcess")
	child.Env = append(os.Environ(), handoffHelperEnv+"=1")
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})

	// 子进程拿锁与它会退出都是异步的：先确认锁确实被另一个进程持有。自己抢到锁时
	// 必须立刻放掉，否则接下去的等待对象就变成了自己。
	require.Eventually(t, func() bool {
		err := TryAcquire()
		if err == nil {
			Release()
			return false
		}
		return errors.Is(err, ErrAnotherInstance)
	}, 10*time.Second, 20*time.Millisecond, "子进程必须持有同一把会话级互斥量")

	require.NoError(t, AcquireAfterRestart(10*time.Second), "交接失败说明新实例永远起不来")
	t.Cleanup(Release)

	require.NoError(t, child.Wait(), "旧实例必须按交接请求正常退出")
}
