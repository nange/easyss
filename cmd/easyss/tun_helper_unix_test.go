//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fdTestSocketPath 在独立目录中返回一个较短的 socket 路径：Unix socket 的
// sun_path 长度限制约为 104 字节，而 t.TempDir() 会嵌入测试名，其长度在
// macOS 上足以超出该限制。
func fdTestSocketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "easyss-fd")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return filepath.Join(dir, "fd.sock")
}

// TestReceiveFdReportsAFailedHelperImmediately 是针对 fd socket 上盲目等待的
// 回归测试：helper 在能发送 fd 之前就失败（例如创建脚本以非零码退出）时，它
// 远早于父进程 30 秒的 accept 截止时间就失败了，而用户看到的却是超时而不是
// 该失败。现在 helper 通过连接 socket 但不携带 fd 来宣告放弃（参见
// notifyStartFailure），父进程必须立即连同原因一起报告它，这样托盘就不必
// 让用户去翻日志文件。
func TestReceiveFdReportsAFailedHelperImmediately(t *testing.T) {
	const reason = `run create script: exit status 1: "[create_tun_dev] failed near: route"`

	socketPath := fdTestSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck

	notified := make(chan struct{})
	go func() {
		defer close(notified)
		notifyStartFailure(socketPath, errors.New(reason))
	}()

	start := time.Now()
	_, err = ReceiveFd(listener)
	elapsed := time.Since(start)
	<-notified

	require.Error(t, err, "a connection that carries no fd is a failed helper, not a started one")
	require.Less(t, elapsed, 5*time.Second,
		"the parent waited out its accept deadline instead of failing as soon as the helper gave up")
	require.Contains(t, err.Error(), "failed near: route",
		"the failure reason the helper sent has to reach the caller: it is what the tray notification shows")
}

// TestReceiveFdReportsAGiveUpWithoutReason 覆盖无法给出原因的 helper：仅凭
// 这次连接本身也必须让启动失败，而不是让父进程等待一个永远不会到来的 fd。
func TestReceiveFdReportsAGiveUpWithoutReason(t *testing.T) {
	socketPath := fdTestSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck

	notified := make(chan struct{})
	go func() {
		defer close(notified)
		notifyStartFailure(socketPath, nil)
	}()

	_, err = ReceiveFd(listener)
	<-notified

	require.Error(t, err, "a helper that gave up without a reason still did not start")
}

// TestFailurePayload 保证失败文本可以用于桌面通知：即使失败的平台脚本带有
// 换行，也始终是一行，并且长度不会超过父进程读取的 socket 消息。
func TestFailurePayload(t *testing.T) {
	require.Nil(t, failurePayload(nil), "a helper without a reason sends nothing")

	payload := string(failurePayload(errors.New("run create script: \n  \"bash /tmp/x.sh\":\texit status 1\n")))
	require.Equal(t, `run create script: "bash /tmp/x.sh": exit status 1`, payload)

	// 超过上限时两端都要保留：开头是失败的步骤，结尾是脚本自己的
	// "failed near:" 摘要。
	long := string(failurePayload(errors.New("start of the reason " +
		strings.Repeat("x", 4*maxHelperFailureReason) + " failed near: route")))
	require.Len(t, long, maxHelperFailureReason, "the parent reads exactly one message of this size")
	require.True(t, strings.HasPrefix(long, "start of the reason"), "the front has to survive: %q", long)
	require.True(t, strings.HasSuffix(long, "failed near: route"), "the summary at the back has to survive: %q", long)
	require.Contains(t, long, " ... ")
}

// TestHelperFailureReasonCarriesTheScriptDiagnostics 固定了托盘通知所显示的
// 内容：这里用拒绝一切调用的 stub 工具真实运行当前平台的创建脚本，helper
// 交给父进程的原因必须携带脚本自身的诊断信息——失败的是什么以及它的
// "failed near:" 摘要——而不只是 "exit status 1"。
//
// stub 工具还能防止测试重新配置运行它的机器：linux 脚本只会用到 "ip"，
// darwin 脚本只会用到 "ifconfig" 和 "route"。
func TestHelperFailureReasonCarriesTheScriptDiagnostics(t *testing.T) {
	shell, tools := "bash", []string{"ip"}
	if runtime.GOOS == "darwin" {
		shell, tools = "sh", []string{"ifconfig", "route"}
	}
	if _, err := exec.LookPath(shell); err != nil {
		t.Skipf("%s is unavailable in this environment: %v", shell, err)
	}

	dir := t.TempDir()
	for _, tool := range tools {
		stub := "#!/bin/sh\necho 'stub tool rejects the call' 1>&2\nexit 1\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, tool), []byte(stub), 0o755))
	}

	origPath := os.Getenv("PATH")
	require.NoError(t, os.Setenv("PATH", dir+string(os.PathListSeparator)+origPath))
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })

	err := runCreateScript("tun-easyss-test", "198.18.0.1/16", "198.18.0.1", "192.168.3.1", "", "", "", "")
	require.Error(t, err, "every stubbed tool rejects its call: the script has to report that")

	reason := string(failurePayload(fmt.Errorf("run create script: %w", err)))
	require.Contains(t, reason, "stub tool rejects the call", "the reason has to carry what the script reported")
	require.Contains(t, reason, "failed near:", "the script's summary is the part the user acts on")
	require.Equal(t, 1, strings.Count(reason, "create script"),
		"only giveUp names the step: the error it wraps must not repeat it: %q", reason)
	require.NotContains(t, reason, "\n", "a notification cannot render the script's newlines")
	require.LessOrEqual(t, len(reason), maxHelperFailureReason)
}

// TestReceiveFdReceivesTheSentFd 从另一侧守护同一条路径：放弃信号绝不能
// 让父进程拒绝健康 helper 发来的 fd。
func TestReceiveFdReceivesTheSentFd(t *testing.T) {
	socketPath := fdTestSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck

	pipeReader, pipeWriter, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		pipeReader.Close() //nolint:errcheck
		pipeWriter.Close() //nolint:errcheck
	})

	sent := make(chan error, 1)
	go func() { sent <- sendFdToParent(socketPath, int(pipeReader.Fd())) }()

	fd, err := ReceiveFd(listener)
	require.NoError(t, err)
	require.NoError(t, <-sent, "the helper failed to send its fd")

	// 收到的描述符必须是 "helper" 发送的管道读端，而不只是某个数字。
	received := os.NewFile(uintptr(fd), "received-fd")
	t.Cleanup(func() { received.Close() }) //nolint:errcheck

	_, err = pipeWriter.Write([]byte("tun"))
	require.NoError(t, err)
	buf := make([]byte, 3)
	_, err = io.ReadFull(received, buf)
	require.NoError(t, err)
	require.Equal(t, "tun", string(buf))
}
