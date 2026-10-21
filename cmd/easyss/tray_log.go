//go:build !headless

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

const (
	logTailLines = 50

	// logSnapshotLines 是快照的行数上限，让巨大的日志文件不会整份进入 GUI 编辑器。
	logSnapshotLines = 500

	logSnapshotTimeout = 5 * time.Second
)

// "查看日志"流程的哨兵错误，由托盘转换成面向用户的中文消息。
var (
	errLogFileNotConfigured = errors.New("log file path is empty, configure log.file_path in config.json")
	errNoTerminalEmulator   = errors.New("no supported terminal emulator found")
)

type termCmdStyle int

const (
	// termStyleArgs 以独立参数形式追加命令，如 `alacritty -e tail -n 50 -f path`。
	termStyleArgs termCmdStyle = iota
	// termStyleString 以单个 shell 字符串形式追加命令，如 `xfce4-terminal --command "tail ..."`。
	termStyleString
)

type termLauncher struct {
	bin   string
	args  []string
	style termCmdStyle
}

// termLaunchers 是有序的终端优先列表，$TERMINAL 不可用时使用。顺序把 XDG 默认终端启动器
// 与 Wayland 原生终端放在前面：现代 Wayland 会话里排在后面的 X11 终端通常没装。
var termLaunchers = []termLauncher{
	// 默认终端执行规范（Arch、Omarchy 等）。
	{"xdg-terminal-exec", []string{"--"}, termStyleArgs},
	{"foot", []string{"-e"}, termStyleArgs},
	{"alacritty", []string{"-e"}, termStyleArgs},
	// kitty 无需分隔参数即可接收要运行的程序。
	{"kitty", nil, termStyleArgs},
	{"ghostty", []string{"-e"}, termStyleArgs},
	{"wezterm", []string{"start", "--"}, termStyleArgs},
	{"x-terminal-emulator", []string{"-e"}, termStyleArgs},
	{"gnome-terminal", []string{"--"}, termStyleArgs},
	{"mate-terminal", []string{"--"}, termStyleArgs},
	{"konsole", []string{"-e"}, termStyleArgs},
	{"xfce4-terminal", []string{"--command"}, termStyleString},
	{"lxterminal", []string{"--command"}, termStyleString},
	{"terminator", []string{"--command"}, termStyleString},
	{"tilix", []string{"-e"}, termStyleArgs},
	{"qterminal", []string{"-e"}, termStyleArgs},
	{"xterm", []string{"-e"}, termStyleArgs},
	{"urxvt", []string{"-e"}, termStyleArgs},
	{"st", []string{"-e"}, termStyleArgs},
}

func defaultLogOpener() logOpener {
	return logOpener{
		lookPath: exec.LookPath,
		open: func(path string) error {
			return util.StartDetached(sessionLaunch([]string{"xdg-open", path}))
		},
	}
}

// fallback 报告是否走了快照路径，调用方据此告知用户日志为何不是实时更新。
func (l logOpener) openLogFile(filePath string) (fallback bool, err error) {
	if strings.TrimSpace(filePath) == "" {
		return false, errLogFileNotConfigured
	}

	// 尚不存在的日志文件只会让终端闪一下又关闭，因此改为报告错误。
	if _, statErr := os.Stat(filePath); statErr != nil {
		return false, fmt.Errorf("log file %s: %w", filePath, statErr)
	}

	switch runtime.GOOS {
	case "linux":
		return l.openLogFileLinux(filePath)
	case "windows":
		argv := []string{"cmd", "/c", "start", "powershell", "-NoExit", "-Command",
			fmt.Sprintf("Get-Content -Wait -Tail 100 '%s'", filePath)}
		return false, util.StartDetached(argv)
	case "darwin":
		argv := []string{"osascript",
			"-e", fmt.Sprintf(`tell application "Terminal" to do script "tail -f \"%s\""`, filePath),
			"-e", `tell application "Terminal" to activate`}
		return false, util.StartDetached(argv)
	default:
		return false, fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}
}

// openLogFileLinux 在终端中实时跟踪日志，找不到任何终端时回退到快照查看器，这样在最小化
// 的桌面上菜单项仍能展示内容。
func (l logOpener) openLogFileLinux(filePath string) (fallback bool, err error) {
	argv, resolveErr := l.logViewerArgv(filePath)
	if resolveErr == nil {
		argv = sessionLaunch(argv)
		startErr := util.StartDetached(argv)
		if startErr == nil {
			log.Info("[SYSTRAY] log opened", "cmd", argv)
			return false, nil
		}
		resolveErr = startErr
	}
	log.Warn("[SYSTRAY] cannot open the log in a terminal", "err", resolveErr)

	if snapshotErr := l.openLogSnapshot(filePath); snapshotErr != nil {
		return false, errors.Join(resolveErr, snapshotErr)
	}

	return true, nil
}

// 优先用可用的 $TERMINAL，否则用 termLaunchers 中第一个已安装的条目。
func (l logOpener) logViewerArgv(filePath string) ([]string, error) {
	viewer := []string{"tail", "-n", strconv.Itoa(logTailLines), "-f", filePath}

	if argv, ok := l.terminalFromEnv(viewer); ok {
		return argv, nil
	}

	checked := make([]string, 0, len(termLaunchers))
	for _, entry := range termLaunchers {
		checked = append(checked, entry.bin)
		bin, err := l.lookPath(entry.bin)
		if err != nil {
			continue
		}
		return launcherArgv(bin, entry, viewer), nil
	}

	return nil, fmt.Errorf("%w (tried $TERMINAL and %s)", errNoTerminalEmulator, strings.Join(checked, ", "))
}

// terminalFromEnv 解析 $TERMINAL。已知终端保留其表条目的参数风格（二进制名之后的额外单词
// 会被丢弃，因为它们会落在命令分隔符之后）；未知终端按 xterm 风格的 -e 约定传入命令。
func (l logOpener) terminalFromEnv(viewer []string) ([]string, bool) {
	term := strings.TrimSpace(os.Getenv("TERMINAL"))
	if term == "" {
		return nil, false
	}

	fields := strings.Fields(term)
	base := filepath.Base(fields[0])

	known := false
	for _, entry := range termLaunchers {
		if entry.bin != base {
			continue
		}
		known = true
		if bin, err := l.lookPath(fields[0]); err == nil {
			return launcherArgv(bin, entry, viewer), true
		}
		break
	}

	if !known {
		if bin, err := l.lookPath(fields[0]); err == nil {
			generic := termLauncher{args: []string{"-e"}, style: termStyleArgs}
			return launcherArgv(bin, generic, viewer), true
		}
	}

	log.Warn("[SYSTRAY] $TERMINAL is not usable, falling back to the built-in terminal list", "terminal", term)
	return nil, false
}

func launcherArgv(bin string, l termLauncher, viewer []string) []string {
	argv := make([]string, 0, 1+len(l.args)+len(viewer))
	argv = append(argv, bin)
	argv = append(argv, l.args...)
	if l.style == termStyleString {
		return append(argv, util.ShellJoin(viewer))
	}

	return append(argv, viewer...)
}

// 没有终端可用时的最后手段。
func (l logOpener) openLogSnapshot(filePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), logSnapshotTimeout)
	defer cancel()

	content, err := util.CommandContext(ctx, "tail", "-n", strconv.Itoa(logSnapshotLines), filePath)
	if err != nil {
		return fmt.Errorf("read log tail: %w", err)
	}

	f, err := os.CreateTemp("", "easyss-log-*.log")
	if err != nil {
		return fmt.Errorf("create log snapshot: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := fmt.Fprintln(f, content); err != nil {
		return fmt.Errorf("write log snapshot: %w", err)
	}
	// 托盘可能以 root 运行，而打开快照的应用以桌面用户身份运行。
	if err := os.Chmod(f.Name(), 0o644); err != nil {
		return fmt.Errorf("chmod log snapshot: %w", err)
	}

	if err := l.open(f.Name()); err != nil {
		return fmt.Errorf("open %s: %w", f.Name(), err)
	}
	log.Info("[SYSTRAY] log snapshot opened", "file", f.Name())

	return nil
}
