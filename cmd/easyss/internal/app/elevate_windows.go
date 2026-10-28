//go:build windows

package app

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/windows"
)

// ShellExecuteExW 的标志与显示方式，取值见 shellapi.h。
const (
	seeMaskNoAsync  = 0x00000100 // SEE_MASK_NOASYNC：非 COM 调用方要等启动完成
	seeMaskFlagNoUI = 0x00000400 // SEE_MASK_FLAG_NO_UI：错误由本进程呈现，不弹系统对话框
	swShowNormal    = 1
)

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// shellExecuteInfo 是 SHELLEXECUTEINFOW 的布局：字段顺序与对齐必须与 shellapi.h 一致，
// 否则 64 位下 dwHotKey 之后（hIcon/hProcess）会整体错位。
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
	lpIDList     unsafe.Pointer
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIcon        windows.Handle
	hProcess     windows.Handle
}

// elevateRestart 以管理员权限重启自身：新进程带 -elevated-restart=<载荷> 接管单实例、
// 带 -enable-tun2socks 在启动路径安装 TUN。用户取消 UAC 时返回 errElevationCancelled。
func elevateRestart(a *App) error {
	exe, err := util.ExecutablePath()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return fmt.Errorf("encode verb: %w", err)
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return fmt.Errorf("encode executable path: %w", err)
	}
	params, err := windows.UTF16PtrFromString(restartArgs(a.configFile, newRestartState(a)))
	if err != nil {
		return fmt.Errorf("encode arguments: %w", err)
	}
	// 新进程的工作目录跟着可执行文件走：配置与日志里的相对路径都以它为准。
	dir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return fmt.Errorf("encode working directory: %w", err)
	}

	sei := shellExecuteInfo{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		fMask:        seeMaskFlagNoUI | seeMaskNoAsync,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		lpDirectory:  dir,
		nShow:        swShowNormal,
	}
	return shellExecuteEx(&sei)
}

// newRestartState 抓取"重启后必须保持不变"的运行期选择：服务器、浏览器代理开关、规则与
// 日志级别都只活在内存快照/菜单里，新实例从配置文件读不到。
func newRestartState(a *App) RestartState {
	snap := a.currentConfig()
	st := RestartState{
		enabled:     true,
		serverIndex: snap.DefaultServerIndex(),
		sysProxy:    "off",
		proxyRule:   snap.Routing.ProxyRule,
		logLevel:    snap.Log.Level,
	}
	if a.browserProxyEnabled() {
		st.sysProxy = "on"
	}
	return st
}

// 参数与 main 的 flag 对齐。-elevated-restart 必须用等号形式带载荷（原因见
// RestartState.IsBoolFlag）；引号交给 ComposeCommandLine，配置路径常带空格。
func restartArgs(configFile string, st RestartState) string {
	args := []string{"-elevated-restart=" + st.encode(), "-enable-tun2socks"}
	if configFile != "" {
		args = append(args, "-c", configFile)
	}
	return windows.ComposeCommandLine(args)
}

func shellExecuteEx(sei *shellExecuteInfo) error {
	ret, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(sei)))
	if ret != 0 {
		return nil
	}

	errno, _ := callErr.(windows.Errno)
	switch errno {
	case windows.ERROR_CANCELLED:
		return errElevationCancelled
	case 0:
		return errors.New("shell execute rejected the elevation request")
	}
	return errno
}
