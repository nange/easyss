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
	// logTailLines 是终端显示的末尾行数。
	logTailLines = 50

	// logSnapshotLines 限制为最后兜底回退而写入的快照大小，
	// 这样巨大的日志文件不会整份进入 GUI 编辑器。
	logSnapshotLines = 500

	// logSnapshotTimeout 限制用于快照的 tail 命令的执行时间。
	logSnapshotTimeout = 5 * time.Second
)

// "查看日志"流程的哨兵错误。它们让托盘能把技术性失败
// 转换为面向用户的中文消息（见 friendlyCatLogError）。
var (
	errLogFileNotConfigured = errors.New("log file path is empty, configure log.file_path in config.json")
	errNoTerminalEmulator   = errors.New("no supported terminal emulator found")
)

// termCmdStyle 描述如何告知终端模拟器要运行的命令。
type termCmdStyle int

const (
	// termStyleArgs 以独立参数形式追加命令，
	// 例如 `alacritty -e tail -n 50 -f /path/to/easyss.log`。
	termStyleArgs termCmdStyle = iota
	// termStyleString 以单个 shell 字符串形式追加命令，
	// 例如 `xfce4-terminal --command "tail -n 50 -f '/path/to/easyss.log'"`。
	termStyleString
)

// termLauncher 是终端模拟器表中的一个条目。
type termLauncher struct {
	bin   string
	args  []string
	style termCmdStyle
}

// termLaunchers 是有序的终端模拟器优先列表，当 $TERMINAL 未指定可用终端时使用。
// 顺序把 XDG 默认终端启动器和 Wayland 原生终端放在前面：
// 在现代 Wayland 会话（Hyprland、sway 等）中，排在它们后面的 X11 时代
// 终端通常都没有安装。
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

// lookPath 即 exec.LookPath，放在变量中以便测试能针对一组模拟的已安装终端
// 来解析该表。
var lookPath = exec.LookPath

// openWithDefaultApp 用桌面的默认应用打开文件。它是变量，
// 以便测试无需弹出 GUI 窗口即可覆盖回退逻辑。
var openWithDefaultApp = func(path string) error {
	argv := sessionLaunch([]string{"xdg-open", path})

	return util.StartDetached(argv)
}

// openLogFile 为用户打开日志文件：在终端模拟器中实时跟踪它，
// 或者 —— 当没有可用的终端模拟器时 —— 以快照形式在桌面的默认应用中打开。
//
// fallback 报告是否走了快照路径，这样调用方可以告知用户
// 日志为何不是实时更新的。
func openLogFile(filePath string) (fallback bool, err error) {
	if strings.TrimSpace(filePath) == "" {
		return false, errLogFileNotConfigured
	}

	// 尚不存在的日志文件只会让终端闪一下又关闭，因此改为报告错误。
	if _, statErr := os.Stat(filePath); statErr != nil {
		return false, fmt.Errorf("log file %s: %w", filePath, statErr)
	}

	switch runtime.GOOS {
	case "linux":
		return openLogFileLinux(filePath)
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

// openLogFileLinux 在终端模拟器中实时跟踪日志。当找不到任何终端模拟器时，
// 回退到快照查看器，这样即使在最小化的桌面上菜单项仍能展示内容。
func openLogFileLinux(filePath string) (fallback bool, err error) {
	argv, resolveErr := logViewerArgv(filePath)
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

	if snapshotErr := openLogSnapshot(filePath); snapshotErr != nil {
		return false, errors.Join(resolveErr, snapshotErr)
	}

	return true, nil
}

// logViewerArgv 返回在终端模拟器中实时跟踪 filePath 的命令：
// 优先使用可用的 $TERMINAL，否则使用 termLaunchers 中第一个已安装的条目。
func logViewerArgv(filePath string) ([]string, error) {
	viewer := []string{"tail", "-n", strconv.Itoa(logTailLines), "-f", filePath}

	if argv, ok := terminalFromEnv(viewer); ok {
		return argv, nil
	}

	checked := make([]string, 0, len(termLaunchers))
	for _, l := range termLaunchers {
		checked = append(checked, l.bin)
		bin, err := lookPath(l.bin)
		if err != nil {
			continue
		}
		return launcherArgv(bin, l, viewer), nil
	}

	return nil, fmt.Errorf("%w (tried $TERMINAL and %s)", errNoTerminalEmulator, strings.Join(checked, ", "))
}

// terminalFromEnv 解析 $TERMINAL 指定的终端。已知终端保留其表条目的参数风格
// （二进制名之后的额外单词会被丢弃，因为它们会落在命令分隔符之后）；
// 未知终端则按 xterm 风格的 -e 约定传入命令。
func terminalFromEnv(viewer []string) ([]string, bool) {
	term := strings.TrimSpace(os.Getenv("TERMINAL"))
	if term == "" {
		return nil, false
	}

	fields := strings.Fields(term)
	base := filepath.Base(fields[0])

	known := false
	for _, l := range termLaunchers {
		if l.bin != base {
			continue
		}
		known = true
		if bin, err := lookPath(fields[0]); err == nil {
			return launcherArgv(bin, l, viewer), true
		}
		break
	}

	if !known {
		if bin, err := lookPath(fields[0]); err == nil {
			generic := termLauncher{args: []string{"-e"}, style: termStyleArgs}
			return launcherArgv(bin, generic, viewer), true
		}
	}

	log.Warn("[SYSTRAY] $TERMINAL is not usable, falling back to the built-in terminal list", "terminal", term)
	return nil, false
}

// launcherArgv 为单个终端模拟器构建完整的 argv。
func launcherArgv(bin string, l termLauncher, viewer []string) []string {
	argv := make([]string, 0, 1+len(l.args)+len(viewer))
	argv = append(argv, bin)
	argv = append(argv, l.args...)
	if l.style == termStyleString {
		return append(argv, util.ShellJoin(viewer))
	}

	return append(argv, viewer...)
}

// sessionLaunch 在 easyss 以 root 运行时（pkexec/sudo 提权，例如启用 TUN），
// 把命令交给桌面用户执行，并带上提权时丢失的会话环境。
// 没有 XDG_RUNTIME_DIR，Wayland 终端根本无法连接合成器。
// 当无法确定用户时，命令原样返回。
func sessionLaunch(argv []string) []string {
	if runtime.GOOS != "linux" || !IsRoot() {
		return argv
	}

	username, uid, ok := util.SessionUser()
	if !ok {
		log.Warn("[SYSTRAY] cannot determine the desktop user, launching as root")
		return argv
	}

	launch := []string{"runuser", "-u", username, "--", "env"}
	launch = append(launch, util.SessionEnv(username, uid)...)

	return append(launch, argv...)
}

// openLogSnapshot 把日志的最后 logSnapshotLines 行写入临时文件，
// 并在桌面的默认应用中打开它。这是没有终端模拟器时的最后手段。
func openLogSnapshot(filePath string) error {
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

	if err := openWithDefaultApp(f.Name()); err != nil {
		return fmt.Errorf("open %s: %w", f.Name(), err)
	}
	log.Info("[SYSTRAY] log snapshot opened", "file", f.Name())

	return nil
}
