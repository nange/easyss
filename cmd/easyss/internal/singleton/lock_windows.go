//go:build !headless && windows

package singleton

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nange/easyss/v3/log"
	"golang.org/x/sys/windows"
)

// 必须留在会话级命名空间：创建 Global\ 对象要求 SeCreateGlobalPrivilege，非提权进程没有
// 该权限，CreateMutex 会以 ACCESS_DENIED 失败——而 Acquire 把它当致命错误直接退出进程。
const mutexName = `Local\Easyss_Singleton`

// instanceLock 是一把命名互斥量。名字可注入：测试用独立名字，既不与开发机上正在运行的
// Easyss 抢同一把锁，也不会把它错当成"另一个实例"。
type instanceLock struct {
	name   string
	handle windows.Handle
}

// appLock 是进程唯一的生产锁，四个导出函数都落在它上面。
var appLock = &instanceLock{name: mutexName}

// TryAcquire 创建确保同一时刻只运行一个应用实例的命名互斥量。
// 互斥量已存在时返回 ErrAnotherInstance，否则返回底层错误。
func TryAcquire() error { return appLock.tryAcquire() }

// Acquire 获取单实例锁，锁不可用时退出进程。
func Acquire() {
	err := TryAcquire()
	switch {
	case err == nil:
		return
	case lockHeldElsewhere(err):
		// ACCESS_DENIED 同样是"锁在别的账户手里"：OTS 提权后的实例属于另一个用户，
		// 用户再点一次快捷方式时应安静退出，而不是当成启动失败。
		log.Warn("[EASYSS-V3] another instance is already running, exiting", "err", err)
		os.Exit(0)
	default:
		log.Error("[EASYSS-V3] failed to create mutex", "err", err)
		os.Exit(1)
	}
}

// Release 释放命名互斥量。
func Release() { appLock.release() }

// AcquireAfterRestart 等前一个实例退出后接管单实例锁：以管理员权限重启的新实例用它，
// 否则 Acquire 会因为旧实例还没退完而直接结束自己。
func AcquireAfterRestart(timeout time.Duration) error { return appLock.acquireAfterRestart(timeout) }

func (l *instanceLock) tryAcquire() error {
	name, _ := windows.UTF16PtrFromString(l.name)
	handle, err := windows.CreateMutex(nil, false, name)
	switch {
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return ErrAnotherInstance
	case err != nil:
		return err
	}
	l.handle = handle
	return nil
}

func (l *instanceLock) release() {
	if l.handle != 0 {
		_ = windows.CloseHandle(l.handle)
		l.handle = 0
	}
}

// lockHeldElsewhere 报告 err 是否只意味着"锁在别处"。ACCESS_DENIED 也算：标准用户输入
// 管理员凭据提权（over-the-shoulder）后，新进程属于另一个账户，打不开旧实例按默认 DACL
// 创建的互斥量——此时唯一可行的动作是等旧实例退出，而不是立刻把它当致命错误放弃。
func lockHeldElsewhere(err error) bool {
	return errors.Is(err, ErrAnotherInstance) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func (l *instanceLock) acquireAfterRestart(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := l.tryAcquire()
		switch {
		case err == nil:
			return nil
		case !lockHeldElsewhere(err):
			return err
		case time.Now().After(deadline):
			return fmt.Errorf("the previous instance did not release the lock within %s: %w", timeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
