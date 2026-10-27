//go:build windows

package tunhelper

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/windows"
)

// IsRoot 报告当前进程是否已提权。Windows 没有 root，只有 UAC 提升后的管理员令牌；
// 未提权时 TUN 必须走 helper，不能像 darwin/linux 那样假定有权限直接创建设备。
func IsRoot() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Helper 是一次提权 TUN helper 会话的父进程句柄：关闭 Control 即通知 helper 退出，
// Wait 等 helper 完成路由/DNS 清理后返回。
type Helper struct {
	control net.Conn
	done    <-chan error
}

// Control 的写端关闭后，helper 读到 EOF 会停止引擎并执行关闭脚本。
func (h *Helper) Control() io.WriteCloser { return h.control }

func (h *Helper) Wait(timeout time.Duration) error {
	if h == nil || h.done == nil {
		return nil
	}
	select {
	case err := <-h.done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("tun helper did not exit within %s", timeout)
	}
}

// Spawn 通过 ShellExecuteEx("runas") 拉起常驻的提权 helper，并用 loopback 控制连接完成
// 握手：helper 先报一次性 token，父进程回 "go" 后才允许它安装路由，最后等 READY/ERROR。
func Spawn(httpAddr string, timeout time.Duration, logFile, logLevel string) (*Helper, error) {
	exe, err := util.ExecutablePath()
	if err != nil {
		return nil, fmt.Errorf("get executable: %w", err)
	}

	timeout = max(timeout, 10*time.Second)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen control: %w", err)
	}
	defer listener.Close() //nolint:errcheck

	token, err := newControlToken()
	if err != nil {
		return nil, fmt.Errorf("generate control token: %w", err)
	}

	args := []string{
		"tun-helper",
		"--tun-http-addr", httpAddr,
		"--tun-control-addr", listener.Addr().String(),
		"--tun-control-token", token,
	}
	if logFile != "" {
		args = append(args, "--log-file", logFile)
	}
	if logLevel != "" {
		args = append(args, "--log-level", logLevel)
	}

	log.Info("[SYSTRAY] spawning elevated tun helper", "exe", exe, "httpAddr", httpAddr)
	proc, err := shellExecuteRunAs(exe, args)
	if err != nil {
		return nil, err
	}

	// 进程句柄只归这个 goroutine 所有：Wait 通过 done 取结果，避免在清理路径上重复关闭句柄。
	done := make(chan error, 1)
	go func() { done <- waitProcess(proc) }()

	conn, err := acceptHelperControl(listener, token, done, timeout)
	if err != nil {
		return nil, err
	}

	// 与 unix 的 ReceiveFd 对齐：创建脚本可能比控制握手慢，但不应无限等。
	_ = conn.SetReadDeadline(time.Now().Add(max(timeout, 30*time.Second)))
	status, err := bufio.NewReader(conn).ReadString('\n')
	_ = conn.SetReadDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read tun helper status: %w", err)
	}

	switch status = strings.TrimSpace(status); {
	case status == "READY":
		return &Helper{control: conn, done: done}, nil
	case strings.HasPrefix(status, "ERROR "):
		reason := strings.TrimSpace(strings.TrimPrefix(status, "ERROR "))
		_ = conn.Close()
		return nil, fmt.Errorf("tun helper: %s", reason)
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected tun helper status %q", status)
	}
}

type controlAccept struct {
	conn net.Conn
	err  error
}

// acceptHelperControl 只接受携带本次 token 的连接；错误 token 直接丢弃，不进入握手。
func acceptHelperControl(listener net.Listener, token string, done <-chan error, timeout time.Duration) (net.Conn, error) {
	accepted := make(chan controlAccept, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				accepted <- controlAccept{err: err}
				return
			}

			_ = conn.SetReadDeadline(time.Now().Add(tunControlIOTimeout))
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil || strings.TrimSpace(line) != token {
				_ = conn.Close()
				continue
			}
			_ = conn.SetReadDeadline(time.Time{}) //nolint:errcheck

			// helper 必须先拿到 go 才能继续；写入失败说明这条连接已不可用，丢弃后继续等。
			_ = conn.SetWriteDeadline(time.Now().Add(tunControlIOTimeout))
			if _, err := io.WriteString(conn, "go\n"); err != nil {
				_ = conn.Close()
				continue
			}
			_ = conn.SetWriteDeadline(time.Time{}) //nolint:errcheck
			accepted <- controlAccept{conn: conn}
			return
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case r := <-accepted:
		if r.err != nil {
			return nil, fmt.Errorf("wait for tun helper control: %w", r.err)
		}
		return r.conn, nil
	case err := <-done:
		drainAccepted(accepted)
		return nil, fmt.Errorf("tun helper exited before control handshake: %w", err)
	case <-timer.C:
		drainAccepted(accepted)
		return nil, fmt.Errorf("timeout waiting for tun helper control (user may have cancelled elevation)")
	}
}

// 连接可能已被 accept goroutine 放进 channel，而外层因进程退出/超时先返回；这里补一次关闭。
func drainAccepted(accepted <-chan controlAccept) {
	select {
	case r := <-accepted:
		if r.conn != nil {
			_ = r.conn.Close()
		}
	default:
	}
}

func newControlToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func waitProcess(proc windows.Handle) error {
	defer windows.CloseHandle(proc) //nolint:errcheck

	if _, err := windows.WaitForSingleObject(proc, windows.INFINITE); err != nil {
		return err
	}

	var code uint32
	if err := windows.GetExitCodeProcess(proc, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("exit code %d", code)
	}
	return nil
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	seeMaskFlagNoUI       = 0x00000400
	swHide                = 0
)

// shellExecuteInfo 镜像 SHELLEXECUTEINFOW。字段顺序与 64 位对齐必须保持一致，cbSize
// 由 unsafe.Sizeof 填入；新增字段时同步核对 shellapi.h。
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIcon        windows.Handle
	hProcess     windows.Handle
}

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// shellExecuteRunAs 用 UAC 提权启动当前 exe，并返回可等待的进程句柄。
// SEE_MASK_FLAG_NO_UI 只抑制 ShellExecute 自己的错误弹窗，UAC 确认框仍会出现。
func shellExecuteRunAs(exe string, args []string) (windows.Handle, error) {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return 0, err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	params, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return 0, err
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return 0, err
	}

	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync | seeMaskFlagNoUI,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		lpDirectory:  dir,
		nShow:        swHide,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))

	r1, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if r1 == 0 {
		switch {
		case errors.Is(callErr, windows.ERROR_CANCELLED):
			return 0, fmt.Errorf("%w: elevation cancelled by user", ErrStartup)
		case errors.Is(callErr, windows.ERROR_ACCESS_DENIED), errors.Is(callErr, windows.ERROR_ELEVATION_REQUIRED):
			return 0, fmt.Errorf("%w: ShellExecuteExW runas: %v", fs.ErrPermission, callErr)
		}
		if callErr == nil || errors.Is(callErr, windows.ERROR_SUCCESS) {
			callErr = windows.GetLastError()
		}
		return 0, fmt.Errorf("ShellExecuteExW runas: %w", callErr)
	}
	if info.hProcess == 0 {
		return 0, fmt.Errorf("ShellExecuteExW runas: empty process handle")
	}
	return info.hProcess, nil
}
