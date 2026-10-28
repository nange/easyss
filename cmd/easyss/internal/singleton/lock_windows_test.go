//go:build windows && !headless

package singleton

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// 用例一律用独立的对象名：开发机上跑着 Easyss 时，生产名会让用例把真实实例当成
// "另一个实例"，go test 时好时坏。
const (
	handoffHelperEnv  = "EASYSS_SINGLETON_HANDOFF_HELPER"
	handoffHelperName = "EASYSS_SINGLETON_HANDOFF_NAME"
)

func newTestLock(t *testing.T) *instanceLock {
	t.Helper()
	name := `Local\Easyss_Test_` + strings.NewReplacer("/", "_", `\`, "_").Replace(t.Name())
	l := &instanceLock{name: name}
	t.Cleanup(l.release)
	return l
}

func TestTryAcquireRejectsTheSecondLock(t *testing.T) {
	first := newTestLock(t)
	require.NoError(t, first.tryAcquire())

	second := newTestLock(t)
	require.ErrorIs(t, second.tryAcquire(), ErrAnotherInstance, "同名锁的第二个持有者必须被拒绝")
}

func TestReleaseLetsAnotherInstanceIn(t *testing.T) {
	first := newTestLock(t)
	require.NoError(t, first.tryAcquire())

	first.release()

	second := newTestLock(t)
	require.NoError(t, second.tryAcquire(), "释放后新实例必须能拿到锁")
}

// TestLockHeldElsewhere 固定"等待 ≠ 失败"的分类：OTS 提权后新进程属于另一个账户，
// 打不开旧实例按默认 DACL 创建的互斥量（ACCESS_DENIED），只能等旧实例退出；
// 其它错误才是真的起不来。
func TestLockHeldElsewhere(t *testing.T) {
	require.True(t, lockHeldElsewhere(ErrAnotherInstance))
	require.True(t, lockHeldElsewhere(windows.ERROR_ACCESS_DENIED))
	require.False(t, lockHeldElsewhere(errors.New("boom")))
}

// TestAcquireAfterRestartWithoutAnotherInstance 固定"没有旧实例时直接拿到锁"：用户手动
// 双击或上一次交接已完成后，新进程不该为此空等一个超时。
func TestAcquireAfterRestartWithoutAnotherInstance(t *testing.T) {
	l := newTestLock(t)
	require.NoError(t, l.acquireAfterRestart(time.Second))
}

// TestAcquireAfterRestartWaitsForAnotherProcess 跨进程跑一遍接管：旧实例持锁、随后按自己的
// 退出流程释放，新实例必须等它退完再拿到锁。提权重启依赖的正是这段等待——抢锁失败就退出
// 会让用户"点了 UAC 之后什么都没有"。
func TestAcquireAfterRestartWaitsForAnotherProcess(t *testing.T) {
	if os.Getenv(handoffHelperEnv) == "1" {
		// 旧实例：持锁一段时间后自行退出，模拟托盘退出流程（撤代理 → 拆 TUN → 停核心）。
		l := &instanceLock{name: os.Getenv(handoffHelperName)}
		if err := l.tryAcquire(); err != nil {
			os.Exit(3)
		}
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}

	lock := newTestLock(t)
	child := exec.Command(os.Args[0], "-test.run=TestAcquireAfterRestartWaitsForAnotherProcess")
	child.Env = append(os.Environ(), handoffHelperEnv+"=1", handoffHelperName+"="+lock.name)
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})

	// 等子进程真正拿住锁；自己抢到时立刻放掉，否则接下去的等待对象就成了自己。
	require.Eventually(t, func() bool {
		err := lock.tryAcquire()
		if err == nil {
			lock.release()
			return false
		}
		return errors.Is(err, ErrAnotherInstance)
	}, 10*time.Second, 20*time.Millisecond, "子进程必须持有同一把会话级互斥量")

	require.NoError(t, lock.acquireAfterRestart(10*time.Second), "接管失败说明提权重启永远起不来")
	require.NoError(t, child.Wait(), "旧实例必须正常退出")
}
