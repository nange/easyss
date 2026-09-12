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
)

// fakeBin is the executable path fakeLookPath reports, and the one every
// expectation below is written with. It stays POSIX style on every platform:
// the terminal table it feeds is used on linux only.
func fakeBin(name string) string {
	return "/usr/bin/" + name
}

// binName strips the directory from a path, treating the POSIX and the
// Windows separator alike so that the fake below behaves the same everywhere.
func binName(path string) string {
	return path[strings.LastIndexAny(path, `/\`)+1:]
}

// fakeLookPath simulates a PATH holding exactly the given executables.
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
	// The fakes have to resolve the same executable on every platform, which
	// is why the separator handling is asserted here instead of relying on
	// filepath, whose Windows build also accepts backslashes.
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
			// The XDG launcher is preferred over the Wayland terminals below
			// it: it is what the session itself would use.
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
			// Terminals that only take one shell string get the command
			// joined and quoted.
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
	// The message has to name what was probed: the previous version only
	// reported "no supported terminal emulator found", which gave no hint
	// about why the log viewer refused to open.
	for _, bin := range []string{"xdg-terminal-exec", "alacritty", "foot", "gnome-terminal"} {
		if !strings.Contains(err.Error(), bin) {
			t.Fatalf("error %q should list the probed terminal %q", err, bin)
		}
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/home/nange/Easyss/easyss.log", "/home/nange/Easyss/easyss.log"},
		{"", "''"},
		{"/tmp/a b.log", "'/tmp/a b.log'"},
		{"/tmp/it's.log", `'/tmp/it'\''s.log'`},
		{"/tmp/$HOME.log", "'/tmp/$HOME.log'"},
		{"/tmp/back\\slash.log", "'/tmp/back\\slash.log'"},
	}

	for _, c := range cases {
		if got := shellQuote(c.in); got != c.want {
			t.Fatalf("shellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestShellJoin(t *testing.T) {
	got := shellJoin([]string{"tail", "-n", "50", "-f", "/tmp/a b.log"})
	if want := "tail -n 50 -f '/tmp/a b.log'"; got != want {
		t.Fatalf("shellJoin = %q, want %q", got, want)
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

// writeTestLog writes a log file with lines "line 1" .. "line N".
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

// stubDefaultApp captures the path handed to the desktop's default
// application instead of opening a window.
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
	// The tray may run as root, so the snapshot has to be readable by the
	// desktop user that opens it.
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

// TestOpenLogFileFallsBackWithoutTerminal covers the whole flow on a desktop
// without any of the supported terminal emulators: the log is opened as a
// snapshot instead of failing.
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
	if err := startDetached(nil); err == nil {
		t.Fatal("expected an error for an empty command")
	}
	if err := startDetached([]string{filepath.Join(t.TempDir(), "does-not-exist")}); err == nil {
		t.Fatal("expected an error for a missing executable")
	}

	if runtime.GOOS == "windows" {
		t.Skip("the true(1) helper is not available on windows")
	}
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("true not found: %v", err)
	}
	// Must return without waiting for the child.
	if err := startDetached([]string{trueBin}); err != nil {
		t.Fatalf("startDetached failed: %v", err)
	}
}

// TestLogViewerArgvOnHost resolves the table against the real PATH of the
// machine running the tests, which is what the tray does at runtime. It is
// skipped on a host without any terminal emulator.
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
