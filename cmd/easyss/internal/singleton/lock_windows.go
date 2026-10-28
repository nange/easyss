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

const (
	// 必须留在会话级命名空间：创建 Global\ 对象要求 SeCreateGlobalPrivilege，非提权进程没有
	// 该权限，CreateMutex 会以 ACCESS_DENIED 失败——而 Acquire 把它当致命错误直接退出进程。
	mutexName = `Local\Easyss_Singleton`
	// 提权重启的新实例用它通知旧实例让位；两侧都不需要提权，Local\ 即可。
	restartEventName = `Local\Easyss_Restart`
)

var (
	winLockHandle    windows.Handle
	winRestartHandle windows.Handle
)

// TryAcquire 创建确保同一时刻只运行一个应用实例的命名互斥量。
// 互斥量已存在时返回 ErrAnotherInstance，否则返回底层错误。
func TryAcquire() error {
	// 交接事件必须先于互斥量存在：新实例的 RequestRestart 会先创建再设置它，设置完就
	// 关闭自己的句柄；没人持有句柄的事件随即销毁，信号随之丢失，旧实例永远等不到接管。
	if err := ensureRestartEvent(); err != nil {
		return err
	}

	name, _ := windows.UTF16PtrFromString(mutexName)
	handle, err := windows.CreateMutex(nil, false, name)
	switch {
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		// 没抢到锁就不持有事件：持有者那份句柄足以让对象存活。
		closeRestartEvent()
		return ErrAnotherInstance
	case err != nil:
		closeRestartEvent()
		return err
	}
	winLockHandle = handle
	return nil
}

// Acquire 获取单实例锁，锁不可用时退出进程。
func Acquire() {
	err := TryAcquire()
	switch {
	case err == nil:
		return
	case errors.Is(err, ErrAnotherInstance):
		log.Warn("[EASYSS-V3] another instance is already running, exiting")
		os.Exit(0)
	default:
		log.Error("[EASYSS-V3] failed to create mutex", "err", err)
		os.Exit(1)
	}
}

// Release 释放命名互斥量与交接事件。
func Release() {
	if winLockHandle != 0 {
		_ = windows.CloseHandle(winLockHandle)
		winLockHandle = 0
	}
	closeRestartEvent()
}

// RequestRestart 请正在运行的实例退出。提权重启的新实例必须在抢锁之前调用它，否则
// Acquire 会因为旧实例还没退完而直接结束自己。
func RequestRestart() error {
	h, err := createRestartEvent()
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if err := windows.SetEvent(h); err != nil {
		return fmt.Errorf("signal restart event: %w", err)
	}
	return nil
}

// WaitRestartRequest 阻塞到有新实例请求接管。返回 false 表示事件对象建不起来，
// 调用方只记日志即可：本实例继续提供服务，交接失败不需要任何清理。
func WaitRestartRequest() bool {
	h, err := createRestartEvent()
	if err != nil {
		log.Error("[EASYSS-V3] create restart event", "err", err)
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if _, err := windows.WaitForSingleObject(h, windows.INFINITE); err != nil {
		log.Error("[EASYSS-V3] wait for restart request", "err", err)
		return false
	}
	return true
}

// AcquireAfterRestart 请旧实例退出，等它释放互斥量后接管单实例锁。超时返回错误而不再等：
// 旧实例可能卡在拆除里，让两个实例同时绑本地端口比启动失败更难查。
func AcquireAfterRestart(timeout time.Duration) error {
	if err := RequestRestart(); err != nil {
		return err
	}

	deadline := time.Now().Add(timeout)
	for {
		switch err := TryAcquire(); {
		case err == nil:
			return nil
		case !errors.Is(err, ErrAnotherInstance):
			return err
		case time.Now().After(deadline):
			return fmt.Errorf("the running instance did not release the lock within %s: %w", timeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ensureRestartEvent 让锁持有者终身持有一个事件句柄，交接信号才不会因为对象没人持有而丢失。
func ensureRestartEvent() error {
	if winRestartHandle != 0 {
		return nil
	}
	h, err := createRestartEvent()
	if err != nil {
		return err
	}
	winRestartHandle = h
	return nil
}

func closeRestartEvent() {
	if winRestartHandle != 0 {
		_ = windows.CloseHandle(winRestartHandle)
		winRestartHandle = 0
	}
}

func createRestartEvent() (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString(restartEventName)
	// 事件已存在是正常情况（交接的两侧都会打开它）：CreateEvent 仍然返回有效句柄，
	// 只是把 ERROR_ALREADY_EXISTS 当成错误一并报回来。
	h, err := windows.CreateEvent(nil, 0, 0, name)
	switch {
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return h, nil
	case err != nil:
		return 0, fmt.Errorf("create restart event: %w", err)
	case h == 0:
		return 0, errors.New("create restart event: invalid handle")
	}
	return h, nil
}
