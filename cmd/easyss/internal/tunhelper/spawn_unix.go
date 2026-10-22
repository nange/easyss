//go:build darwin || linux

package tunhelper

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

func IsRoot() bool {
	return os.Geteuid() == 0
}

// tunHelperElevator 抽象提权 TUN helper 的启动方式：Linux 上为 pkexec，macOS 上为带管理员
// 权限的 osascript。其余（FIFO 生命周期、等待循环、清理）由 spawnTunHelper 共享。
type tunHelperElevator struct {
	// label 在错误消息中命名该提权器（"pkexec"/"osascript"）。
	label   string
	command func(innerCmd string) *exec.Cmd
	// innerCmd 必须把 helper 以分离方式后台运行：`'<exe>' <args> < '<fifo>'`，并丢弃输出。
	innerCmd func(exe, helperArgs, fifoPath string) string
	// Socket 生命周期钩子，该平台不需要时为 nil（Linux 用抽象 socket，没有文件系统条目）。
	beforeListen  func(fdSocketPath string)
	afterListen   func(fdSocketPath string)
	cleanupSocket func(fdSocketPath string)
}

// spawnTunHelper 通过平台提权器启动常驻的 TUN helper：FIFO 关闭写端即通知它退出，TUN 文件
// 描述符经 Unix socket 接收。httpAddr 是本地 HTTP 入口的拨号地址，helper 用它 GET /tun 取配置。
func spawnTunHelper(ev tunHelperElevator, httpAddr string, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	log.Info("[SYSTRAY] SpawnTunHelper called",
		"httpAddr", httpAddr, "fdSocket", fdSocketPath,
		"logFile", logFile, "logLevel", logLevel)

	exe, err := util.ExecutablePath()
	if err != nil {
		return nil, nil, fmt.Errorf("get executable: %w", err)
	}

	fifoPath := fmt.Sprintf("/tmp/easyss-tun-ctrl-%d.fifo", os.Getpid())
	os.Remove(fifoPath) //nolint:errcheck
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		return nil, nil, fmt.Errorf("mkfifo %s: %w", fifoPath, err)
	}

	// 以写模式打开会阻塞到 helper 打开读端，因此放到 goroutine 里。
	fifoCh := openFifoForWriteAsync(fifoPath)

	if ev.beforeListen != nil {
		ev.beforeListen(fdSocketPath)
	}
	fdListener, err := net.Listen("unix", fdSocketPath)
	if err != nil {
		releaseFifoOpen(fifoPath, fifoCh)
		os.Remove(fifoPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("listen on %s: %w", fdSocketPath, err)
	}
	if ev.afterListen != nil {
		ev.afterListen(fdSocketPath)
	}

	helperArgs := []string{
		"tun-helper",
		"--tun-http-addr", httpAddr,
		"--tun-fd-socket", fdSocketPath,
	}
	if logFile != "" {
		helperArgs = append(helperArgs, "--log-file", logFile)
	}
	if logLevel != "" {
		helperArgs = append(helperArgs, "--log-level", logLevel)
	}

	// 提权器把 helper 放入后台后立即返回，helper 继续存活并监视其 stdin（FIFO）。
	elevCmd := ev.command(ev.innerCmd(exe, util.ShellJoin(helperArgs), fifoPath))
	var elevOut, elevErr bytes.Buffer
	elevCmd.Stdout = &elevOut
	elevCmd.Stderr = &elevErr
	if err := elevCmd.Start(); err != nil {
		fdListener.Close() //nolint:errcheck
		releaseFifoOpen(fifoPath, fifoCh)
		os.Remove(fifoPath) //nolint:errcheck
		if ev.cleanupSocket != nil {
			ev.cleanupSocket(fdSocketPath)
		}
		return nil, nil, fmt.Errorf("start %s: %w", ev.label, err)
	}

	// 在后台等待提权器：提前退出（认证被取消/拒绝、提权器错误）能立即以真实原因呈现，
	// 而不是盲等 FIFO 超时。
	elevCh := make(chan error, 1)
	go func() {
		elevCh <- elevCmd.Wait()
	}()

	// 等待 FIFO 写端被打开（helper 已打开读端）。用户取消认证对话框时这里会带着底层错误
	// 提前返回。
	timeout = max(timeout, 10*time.Second)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case r := <-fifoCh:
			if r.err != nil {
				elevCmd.Process.Kill() //nolint:errcheck
				fdListener.Close()     //nolint:errcheck
				os.Remove(fifoPath)    //nolint:errcheck
				if ev.cleanupSocket != nil {
					ev.cleanupSocket(fdSocketPath)
				}
				return nil, nil, fmt.Errorf("open fifo write: %w", r.err)
			}
			return &fifoWriter{File: r.f, path: fifoPath}, fdListener, nil
		case err := <-elevCh:
			if err == nil {
				// 提权器成功；helper 可能在其返回后片刻才启动，因此继续等待 FIFO。
				elevCh = nil
				continue
			}
			// 提权器在 helper 启动前以错误退出（例如用户取消了认证对话框）。
			fdListener.Close() //nolint:errcheck
			releaseFifoOpen(fifoPath, fifoCh)
			os.Remove(fifoPath) //nolint:errcheck
			if ev.cleanupSocket != nil {
				ev.cleanupSocket(fdSocketPath)
			}
			detail := strings.TrimSpace(elevErr.String())
			if detail == "" {
				detail = strings.TrimSpace(elevOut.String())
			}
			if detail != "" {
				return nil, nil, fmt.Errorf("%w: %s: %v: %s", ErrStartup, ev.label, err, detail)
			}
			return nil, nil, fmt.Errorf("%w: %s: %w", ErrStartup, ev.label, err)
		case <-deadline.C:
			// 超时：可能用户取消了认证对话框，或 helper 启动失败。杀掉提权器，使迟到的
			// 授权无法针对即将被移除的 socket 生成 helper。
			elevCmd.Process.Kill() //nolint:errcheck
			fdListener.Close()     //nolint:errcheck
			releaseFifoOpen(fifoPath, fifoCh)
			os.Remove(fifoPath) //nolint:errcheck
			if ev.cleanupSocket != nil {
				ev.cleanupSocket(fdSocketPath)
			}
			return nil, nil, fmt.Errorf("timeout waiting for tun helper (user may have cancelled)")
		}
	}
}
