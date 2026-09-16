//go:build !headless

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/util"
)

// fakeBin 是 fakeLookPath 报告的、也是下面所有预期所用的可执行文件路径。
// 它在所有平台上都保持 POSIX 风格：它填充的终端表只在 linux 上使用。
func fakeBin(name string) string {
	return "/usr/bin/" + name
}

// binName 从路径中剥离目录部分，对 POSIX 和 Windows 分隔符一视同仁，
// 以便下面的 fake 在所有平台上行为一致。
func binName(path string) string {
	return path[strings.LastIndexAny(path, `/\`)+1:]
}

// fakeLookPath 模拟一个只包含给定可执行文件的 PATH。
func fakeLookPath(installed ...string) func(string) (string, error) {
	available := make(map[string]bool, len(installed))
	for _, bin := range installed {
		available[binName(bin)] = true
	}

	return func(name string) (string, error) {
		if available[binName(name)] {
			return fakeBin(binName(name)), nil
		}
		return "", exec.ErrNotFound
	}
}

func TestBinName(t *testing.T) {
	// fake 必须在每个平台上解析出相同的可执行文件，因此这里直接断言分隔符
	// 的处理，而不是依赖 filepath——它的 Windows 版本同样接受反斜杠。
	cases := map[string]string{
		"foot":                      "foot",
		"/usr/bin/foot":             "foot",
		`\usr\bin\foot`:             "foot",
		`C:\Program Files\foot.exe`: "foot.exe",
		"":                          "",
	}

	for in, want := range cases {
		if got := binName(in); got != want {
			t.Fatalf("binName(%q) = %q, want %q", in, got, want)
		}
	}
}

func withLookPath(t *testing.T, lookup func(string) (string, error)) {
	t.Helper()

	previous := lookPath
	lookPath = lookup
	t.Cleanup(func() { lookPath = previous })
}

func TestLogViewerArgv(t *testing.T) {
	const logPath = "/home/nange/Easyss/easyss.log"
	tailArgv := []string{"tail", "-n", "50", "-f", logPath}

	cases := []struct {
		name      string
		terminal  string
		installed []string
		want      []string
	}{
		{
			name:      "omarchy: TERMINAL points at the xdg launcher",
			terminal:  "xdg-terminal-exec",
			installed: []string{"xdg-terminal-exec", "alacritty"},
			want:      append([]string{fakeBin("xdg-terminal-exec"), "--"}, tailArgv...),
		},
		{
			// XDG 启动器优先于其下方的 Wayland 终端：这正是会话本身会使用的。
			name:      "xdg launcher wins without TERMINAL",
			installed: []string{"xdg-terminal-exec", "alacritty", "foot"},
			want:      append([]string{fakeBin("xdg-terminal-exec"), "--"}, tailArgv...),
		},
		{
			name:      "TERMINAL=foot",
			terminal:  "foot",
			installed: []string{"foot", "alacritty"},
			want:      append([]string{fakeBin("foot"), "-e"}, tailArgv...),
		},
		{
			name:      "TERMINAL given as an absolute path",
			terminal:  fakeBin("foot"),
			installed: []string{"foot"},
			want:      append([]string{fakeBin("foot"), "-e"}, tailArgv...),
		},
		{
			name:      "unknown TERMINAL falls back to the xterm -e convention",
			terminal:  "myterm",
			installed: []string{"myterm"},
			want:      append([]string{fakeBin("myterm"), "-e"}, tailArgv...),
		},
		{
			name:      "known TERMINAL that is not installed falls back to the table",
			terminal:  "kitty",
			installed: []string{"alacritty"},
			want:      append([]string{fakeBin("alacritty"), "-e"}, tailArgv...),
		},
		{
			name:      "unknown TERMINAL that is not installed falls back to the table",
			terminal:  "ghostty-ng",
			installed: []string{"foot"},
			want:      append([]string{fakeBin("foot"), "-e"}, tailArgv...),
		},
		{
			name:      "wayland terminals come before the x11 ones",
			installed: []string{"alacritty", "gnome-terminal"},
			want:      append([]string{fakeBin("alacritty"), "-e"}, tailArgv...),
		},
		{
			name:      "gnome-terminal keeps its -- separator",
			installed: []string{"gnome-terminal"},
			want:      append([]string{fakeBin("gnome-terminal"), "--"}, tailArgv...),
		},
		{
			name:      "kitty takes the command without a separator",
			installed: []string{"kitty"},
			want:      append([]string{fakeBin("kitty")}, tailArgv...),
		},
		{
			name:      "wezterm",
			installed: []string{"wezterm"},
			want:      append([]string{fakeBin("wezterm"), "start", "--"}, tailArgv...),
		},
		{
			// 只接受单个 shell 字符串的终端，其命令会被拼接并加引号。
			name:      "xfce4-terminal takes a shell string",
			installed: []string{"xfce4-terminal"},
			want:      []string{fakeBin("xfce4-terminal"), "--command", "tail -n 50 -f " + logPath},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TERMINAL", c.terminal)
			withLookPath(t, fakeLookPath(c.installed...))

			got, err := logViewerArgv(logPath)
			if err != nil {
				t.Fatalf("logViewerArgv returned an error: %v", err)
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("unexpected argv:\n got: %q\nwant: %q", got, c.want)
			}
		})
	}
}

func TestLogViewerArgvQuotesPathsInShellStrings(t *testing.T) {
	t.Setenv("TERMINAL", "")
	withLookPath(t, fakeLookPath("xfce4-terminal"))

	const logPath = "/home/nange/Easyss dir/it's.log"
	got, err := logViewerArgv(logPath)
	if err != nil {
		t.Fatalf("logViewerArgv returned an error: %v", err)
	}

	want := []string{fakeBin("xfce4-terminal"), "--command", `tail -n 50 -f '/home/nange/Easyss dir/it'\''s.log'`}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected argv:\n got: %q\nwant: %q", got, want)
	}
}

func TestLogViewerArgvWithoutTerminal(t *testing.T) {
	t.Setenv("TERMINAL", "")
	withLookPath(t, fakeLookPath())

	_, err := logViewerArgv("/tmp/easyss.log")
	if !errors.Is(err, errNoTerminalEmulator) {
		t.Fatalf("expected errNoTerminalEmulator, got %v", err)
	}
	// 错误消息必须说明探测了哪些程序：旧版本只报告
	// "no supported terminal emulator found"，完全没有提示日志查看器
	// 为什么拒绝打开。
	for _, bin := range []string{"xdg-terminal-exec", "alacritty", "foot", "gnome-terminal"} {
		if !strings.Contains(err.Error(), bin) {
			t.Fatalf("error %q should list the probed terminal %q", err, bin)
		}
	}
}

func TestOpenLogFileErrors(t *testing.T) {
	for _, filePath := range []string{"", "   "} {
		if _, err := openLogFile(filePath); !errors.Is(err, errLogFileNotConfigured) {
			t.Fatalf("expected errLogFileNotConfigured for %q, got %v", filePath, err)
		}
	}

	missing := filepath.Join(t.TempDir(), "not-there.log")
	if _, err := openLogFile(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist for a missing log file, got %v", err)
	}
}

// writeTestLog 写入一个包含 "line 1" .. "line N" 各行的日志文件。
func writeTestLog(t *testing.T, lines int) string {
	t.Helper()

	filePath := filepath.Join(t.TempDir(), "easyss.log")
	content := make([]string, 0, lines)
	for i := 1; i <= lines; i++ {
		content = append(content, fmt.Sprintf("line %d", i))
	}
	if err := os.WriteFile(filePath, []byte(strings.Join(content, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write test log: %v", err)
	}

	return filePath
}

// stubDefaultApp 捕获交给桌面默认应用程序的路径，而不真正打开窗口。
func stubDefaultApp(t *testing.T) *string {
	t.Helper()

	opened := new(string)
	previous := openWithDefaultApp
	openWithDefaultApp = func(path string) error {
		*opened = path
		return nil
	}
	t.Cleanup(func() { openWithDefaultApp = previous })

	return opened
}

func TestOpenLogSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the snapshot fallback is used on linux only")
	}

	const totalLines = logSnapshotLines + 50
	logPath := writeTestLog(t, totalLines)
	opened := stubDefaultApp(t)

	if err := openLogSnapshot(logPath); err != nil {
		t.Fatalf("openLogSnapshot failed: %v", err)
	}
	if *opened == "" {
		t.Fatal("expected the snapshot to be handed to the default application")
	}
	t.Cleanup(func() { _ = os.Remove(*opened) })

	info, err := os.Stat(*opened)
	if err != nil {
		t.Fatalf("snapshot not found: %v", err)
	}
	// 托盘可能以 root 身份运行，因此快照必须对打开它的桌面用户可读。
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("snapshot mode = %o, want 644", got)
	}

	data, err := os.ReadFile(*opened)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	content := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(content) != logSnapshotLines {
		t.Fatalf("snapshot has %d lines, want %d", len(content), logSnapshotLines)
	}
	if content[0] != fmt.Sprintf("line %d", totalLines-logSnapshotLines+1) {
		t.Fatalf("snapshot starts at %q, want the tail of the log", content[0])
	}
	if last := content[len(content)-1]; last != fmt.Sprintf("line %d", totalLines) {
		t.Fatalf("snapshot ends at %q, want line %d", last, totalLines)
	}
}

// TestOpenLogFileFallsBackWithoutTerminal 覆盖在没有安装任何受支持终端模拟器
// 的桌面上的完整流程：日志以快照方式打开，而不是直接失败。
func TestOpenLogFileFallsBackWithoutTerminal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the terminal table is used on linux only")
	}

	logPath := writeTestLog(t, 5)
	t.Setenv("TERMINAL", "")
	withLookPath(t, fakeLookPath())
	opened := stubDefaultApp(t)

	fallback, err := openLogFile(logPath)
	if err != nil {
		t.Fatalf("openLogFile failed: %v", err)
	}
	if !fallback {
		t.Fatal("expected the snapshot fallback to be reported")
	}
	if *opened == "" {
		t.Fatal("expected the snapshot to be handed to the default application")
	}
	t.Cleanup(func() { _ = os.Remove(*opened) })
}

func TestStartDetached(t *testing.T) {
	if err := util.StartDetached(nil); err == nil {
		t.Fatal("expected an error for an empty command")
	}
	if err := util.StartDetached([]string{filepath.Join(t.TempDir(), "does-not-exist")}); err == nil {
		t.Fatal("expected an error for a missing executable")
	}

	if runtime.GOOS == "windows" {
		t.Skip("the true(1) helper is not available on windows")
	}
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("true not found: %v", err)
	}
	// 必须在不等待子进程的情况下返回。
	if err := util.StartDetached([]string{trueBin}); err != nil {
		t.Fatalf("util.StartDetached failed: %v", err)
	}
}

// TestLogViewerArgvOnHost 针对运行测试的机器的真实 PATH 解析终端表，
// 这正是托盘在运行时的行为。在没有终端模拟器的主机上会跳过该测试。
func TestLogViewerArgvOnHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the terminal table is used on linux only")
	}

	const logPath = "/tmp/easyss.log"
	argv, err := logViewerArgv(logPath)
	if err != nil {
		t.Skipf("no terminal emulator available on this host: %v", err)
	}

	if term := strings.TrimSpace(os.Getenv("TERMINAL")); term != "" {
		if bin, lookErr := exec.LookPath(strings.Fields(term)[0]); lookErr == nil && argv[0] != bin {
			t.Fatalf("$TERMINAL=%q should win, got %q", term, argv[0])
		}
	}

	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "tail -n 50 -f") || !strings.Contains(joined, logPath) {
		t.Fatalf("argv %q does not tail %s", argv, logPath)
	}
	if _, err := os.Stat(argv[0]); err != nil {
		t.Fatalf("resolved terminal %q is not executable: %v", argv[0], err)
	}

	t.Logf("resolved terminal argv: %q (TERMINAL=%q)", argv, os.Getenv("TERMINAL"))
}

func TestFriendlyCatLogError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errLogFileNotConfigured, "日志文件未配置：请在 config.json 中设置 log.file_path，日志才会写入文件。"},
		{errNoTerminalEmulator, "未找到可用的终端模拟器：请安装 xdg-terminal-exec、alacritty、foot 等终端，或设置 $TERMINAL 环境变量。"},
		{fs.ErrNotExist, "日志文件不存在：" + fs.ErrNotExist.Error()},
		{fs.ErrPermission, "没有权限读取日志文件：" + fs.ErrPermission.Error()},
		{errors.New("boom"), "打开日志失败：boom"},
	}

	for _, c := range cases {
		if got := friendlyCatLogError(c.err); got != c.want {
			t.Fatalf("friendlyCatLogError(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}
