//go:build darwin || linux

package main

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

// tunHelperElevator 抽象提权 TUN helper 的启动方式：Linux 上为 pkexec，
// macOS 上为带管理员权限的 osascript。两个平台仅在提权命令、把 helper
// 放入后台的 shell 行以及 fd-socket 生命周期上不同；其余一切
// （FIFO 生命周期、等待循环、清理）由 spawnTunHelper 共享。
type tunHelperElevator struct {
	// label 在错误消息中命名该提权器（"pkexec"/"osascript"）。
	label string
	// command 构建运行 innerCmd 的提权命令。
	command func(innerCmd string) *exec.Cmd
	// innerCmd 构建把 helper 放入后台的 shell 行：必须以分离方式运行
	// `'<exe>' <args> < '<fifo>'`，丢弃输出。
	innerCmd func(exe, helperArgs, fifoPath string) string
	// Socket 生命周期钩子，不需要的平台为 nil（Linux 使用抽象 socket，
	// 没有文件系统条目）。
	beforeListen  func(fdSocketPath string)
	afterListen   func(fdSocketPath string)
	cleanupSocket func(fdSocketPath string)
}

// spawnTunHelper 通过平台提权器启动一个常驻的提权 TUN helper 进程。
// 它创建一个 FIFO 用于生命周期信号（关闭写端触发 helper 退出），
// 以及一个用于接收 TUN 文件描述符的 Unix socket。
//
// 返回：
//   - fifoWriter：关闭以通知 helper 关闭
//   - fdListener：接受连接并调用 ReceiveFd 获取 TUN fd
func spawnTunHelper(ev tunHelperElevator, httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	log.Info("[SYSTRAY] SpawnTunHelper called",
		"httpPort", httpPort, "fdSocket", fdSocketPath,
		"logFile", logFile, "logLevel", logLevel)

	exe, err := util.ExecutablePath()
	if err != nil {
		return nil, nil, fmt.Errorf("get executable: %w", err)
	}

	// 创建用于生命周期信号的命名 FIFO。先清理陈旧文件。
	fifoPath := fmt.Sprintf("/tmp/easyss-tun-ctrl-%d.fifo", os.Getpid())
	os.Remove(fifoPath) //nolint:errcheck
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		return nil, nil, fmt.Errorf("mkfifo %s: %w", fifoPath, err)
	}

	// 在 goroutine 中以写模式打开 FIFO（阻塞到 helper 通过 stdin 重定向
	// 以读模式打开它）。
	fifoCh := openFifoForWriteAsync(fifoPath)

	// 创建用于传递 fd 的 Unix socket。
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

	// 构建 helper 命令。helper 以 "tun-helper" 子命令运行，
	// 通过 GET /tun 读取配置，并通过 Unix socket 发送 fd。
	// Stdin 连接到 FIFO。
	tunHTTPAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	helperArgs := []string{
		"tun-helper",
		"--tun-http-addr", tunHTTPAddr,
		"--tun-fd-socket", fdSocketPath,
	}
	if logFile != "" {
		helperArgs = append(helperArgs, "--log-file", logFile)
	}
	if logLevel != "" {
		helperArgs = append(helperArgs, "--log-level", logLevel)
	}

	// 通过提权器启动。helper 被放入后台（&），因此提权器立即返回；
	// helper 保持存活，监视其 stdin（FIFO）等待主进程的生命周期信号。
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

	// 在后台等待提权器，使提前退出（认证被取消/拒绝、提权器错误）
	// 立即以真实原因呈现，而不是盲等 FIFO 超时。
	elevCh := make(chan error, 1)
	go func() {
		elevCh <- elevCmd.Wait()
	}()

	// 等待 FIFO 写端被打开（helper 已打开读端）。
	// 如果用户取消认证对话框，这里会带着底层错误提前返回。
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
				// 提权器成功；helper 可能在其返回后片刻才启动，
				// 因此继续等待 FIFO。
				elevCh = nil
				continue
			}
			// 提权器在 helper 启动前以错误退出
			// （例如用户取消了认证对话框）。
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
				return nil, nil, fmt.Errorf("%s exited before tun helper started: %v: %s", ev.label, err, detail)
			}
			return nil, nil, fmt.Errorf("%s exited before tun helper started: %w", ev.label, err)
		case <-deadline.C:
			// 超时：用户可能取消了认证对话框，或 helper 启动失败。
			// 杀掉提权器，使迟到的授权无法针对即将被移除的 socket
			// 生成 helper。
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
