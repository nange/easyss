package mobile

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// testSimpleConfig 构造可离线启动的最小配置：字面 IP 服务端 + 禁用 IPv6，启动时不发真实 DNS 查询。
// 本地代理端口留 0（不监听）：日志契约与它们无关，而"先探测端口、再让 Start 去 bind"
// 之间隔着 client.New 的初始化，这段时间同机其它测试可能把临时端口占走。
func testSimpleConfig(t *testing.T, logFilePath, logLevel string) *config.SimpleConfig {
	t.Helper()

	return &config.SimpleConfig{
		Server:      "127.0.0.1",
		Password:    "test-password",
		IPV6Rule:    "disable",
		LogFilePath: logFilePath,
		LogLevel:    logLevel,
	}
}

// openFdsFor 返回本进程中指向 path 的打开 fd 数量，第二个返回值报告平台是否支持这种观察。
// 它把"被打开的文件在 Windows 上无法删除"变成可直接断言的信号；不支持 /proc 的平台只能靠 t.TempDir 清理暴露。
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

// TestStartAppliesLogConfig 固定 Start 按 SimpleConfig 装配日志器、Stop 释放它：漏掉装配时
// log_level/log_file_path 被静默忽略，核心只用包级默认 logger（info 级、只写 stdout）。
// 三个可观察后果：debug 不再被过滤、日志文件真的收到记录、Stop 之后句柄被释放。
func TestStartAppliesLogConfig(t *testing.T) {
	ctx := context.Background()

	// 只还原 logger 本身、不走 log.Init：Init 会顺带关掉上一个文件写入器，那样 Stop 漏关也抓不到了。
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
	// 兜底停止核心（显式 Stop 之后的重复调用是空操作）；defer 后进先出，它先于上面那行还原执行。
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

// TestStartFailureReleasesFileOutput 固定 Start 失败也要收尾文件输出：日志器在 runner.Run 之前装配，
// 而失败时 mCore 仍为 nil、Stop 会早退，不自己释放的话写入器仍被包级 logger 引用（可达，GC 不回收），
// 配错一次就不再 Start 的宿主会一直占着日志文件。
func TestStartFailureReleasesFileOutput(t *testing.T) {
	original := log.Logger()
	defer log.SetLogger(original)

	// 占住 SOCKS 端口使 runner.Run 绑定失败。
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

	// 先确认失败路径确实写过文件，否则下面的 fd 断言会退化成恒真式。
	data, err := os.ReadFile(logFile)
	if err != nil || !strings.Contains(string(data), "client core ready") {
		t.Fatalf("failed Start did not write to the log file before failing: %v, content: %q", err, data)
	}

	if n, ok := openFdsFor(t, logFile); ok && n != 0 {
		t.Errorf("failed Start left %d open descriptor(s) on the log file", n)
	}
}
