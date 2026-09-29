package mobile

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// freePort 返回一个当前空闲的 TCP 端口。与 runner 包的测试同样采用
// "先绑定再释放"的方式：绑定失败（例如端口耗尽）会让测试立即失败。
func freePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close() //nolint:errcheck

	return l.Addr().(*net.TCPAddr).Port
}

// testSimpleConfig 构造一份可以离线启动的最小配置：字面 IP 服务端 + 禁用
// IPv6 规则，与 runner 包的测试一致，因此启动过程不会发起任何真实 DNS 查询。
// HTTP 端口显式指定，避免 BuildSimpleConfig 的 socks_port+1000 默认值撞上
// 其它进程占用的端口。
func testSimpleConfig(t *testing.T, logFilePath, logLevel string) *sharedconfig.SimpleConfig {
	t.Helper()

	return &sharedconfig.SimpleConfig{
		Server:      "127.0.0.1",
		Password:    "test-password",
		IPV6Rule:    "disable",
		LocalPort:   freePort(t),
		HTTPPort:    freePort(t),
		LogFilePath: logFilePath,
		LogLevel:    logLevel,
	}
}

// openFdsFor 返回当前进程中指向 path 的打开文件描述符数量，第二个返回值报告该
// 平台是否支持这种观察（读 /proc/self/fd）。它把"被打开的文件在 Windows 上无法
// 删除"这一真实语义，在支持 /proc 的平台上变成可直接断言的信号；其它平台跳过，
// 由 t.TempDir 的清理来承担（见 TestStartAppliesLogConfig）。
func openFdsFor(t *testing.T, path string) (int, bool) {
	t.Helper()

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}

	n := 0
	for _, e := range entries {
		if link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && link == path {
			n++
		}
	}
	return n, true
}

// TestStartAppliesLogConfig 固定"Start 按 SimpleConfig 装配日志器、Stop 释放它"
// 这一契约。
//
// 绑定过去从不调用 log.Init，于是 log_level/log_file_path 被静默忽略：核心只能
// 以包级默认 logger（静态 info 级、只写 stdout）输出，Android 上调不到级别也拿
// 不到日志文件。这里用三个可观察后果把它钉住：debug 级记录不再被过滤、日志文件
// 真的收到记录、Stop 之后文件句柄被释放（最后一点在 Windows 上表现为 t.TempDir
// 的清理失败，被打开的文件无法删除）。
func TestStartAppliesLogConfig(t *testing.T) {
	ctx := context.Background()

	// 只还原包级日志器本身，不走 log.Init：Init 会顺带关闭上一个文件写入器，
	// 用它还原会让"释放日志文件句柄"变成谁都不用负责的事——Stop 漏关时
	// Windows 上的临时目录清理照样能过，测试就抓不到了。
	original := log.Logger()
	defer log.SetLogger(original)

	if log.Logger().Enabled(ctx, slog.LevelDebug) {
		t.Fatal("debug records are enabled before Start")
	}

	logFile := filepath.Join(t.TempDir(), "easyss.log")
	cfg := testSimpleConfig(t, logFile, "debug")

	if err := Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// 兜底：断言失败提前返回时核心也必须被停止（此时下面的显式 Stop 已经执行过，
	// 重复调用是空操作）。defer 后进先出，因此它先于上面的日志器还原执行。
	defer Stop()

	if !log.Logger().Enabled(ctx, slog.LevelDebug) {
		t.Error("log_level from SimpleConfig is not applied: debug records are filtered out")
	}

	const marker = "mobile log config probe"
	log.Info(marker)

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file %s: %v", logFile, err)
	}
	if !strings.Contains(string(data), marker) {
		t.Errorf("log_file_path from SimpleConfig is not applied, file content: %q", data)
	}

	if n, ok := openFdsFor(t, logFile); ok && n == 0 {
		t.Error("the configured log file was never opened")
	}

	Stop()

	if n, ok := openFdsFor(t, logFile); ok && n != 0 {
		t.Errorf("Stop left %d open descriptor(s) on the log file", n)
	}
}

// TestStartFailureReleasesFileOutput 固定"Start 失败也要收尾文件输出"这一契约。
//
// Start 在 runner.Run 之前装配日志器，而启动失败时核心并未建立（mCore 仍为 nil），
// Stop 会在 mCore == nil 时早退，因此失败路径必须自己释放：否则写入器仍被包级
// logger 引用（可达 → GC 不会回收），"配错一次就不再 Start"的宿主会一直占着日志
// 文件。端口被占用正是这条路径，而且在失败之前运行日志已经写过一行。
func TestStartFailureReleasesFileOutput(t *testing.T) {
	original := log.Logger()
	defer log.SetLogger(original)

	// 占住将要监听的 SOCKS 端口，使 runner.Run 在 prebind 阶段失败。保持监听器
	// 打开，直到 Start 返回之后才释放。
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer occupied.Close() //nolint:errcheck
	occupiedPort := occupied.Addr().(*net.TCPAddr).Port

	logFile := filepath.Join(t.TempDir(), "easyss.log")
	cfg := testSimpleConfig(t, logFile, "debug")
	cfg.LocalPort = occupiedPort

	if err := Start(cfg); err == nil {
		Stop()
		t.Fatalf("Start succeeded although port %d is occupied", occupiedPort)
	}

	// 先确认这条失败路径确实写过文件（否则下面的 fd 断言会退化成"文件从未被
	// 打开"的恒真式），再断言句柄已释放。
	data, err := os.ReadFile(logFile)
	if err != nil || !strings.Contains(string(data), "client core ready") {
		t.Fatalf("failed Start did not write to the log file before failing: %v, content: %q", err, data)
	}

	if n, ok := openFdsFor(t, logFile); ok && n != 0 {
		t.Errorf("failed Start left %d open descriptor(s) on the log file", n)
	}
}
