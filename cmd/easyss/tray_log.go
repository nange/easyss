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
	// logTailLines is the number of trailing lines shown by the terminal.
	logTailLines = 50

	// logSnapshotLines bounds the snapshot written for the last-resort
	// fallback, so that a huge log file never reaches a GUI editor whole.
	logSnapshotLines = 500

	// logSnapshotTimeout bounds the tail command used for the snapshot.
	logSnapshotTimeout = 5 * time.Second
)

// Sentinel errors of the "view log" flow. They let the tray turn a technical
// failure into a user-facing Chinese message (see friendlyCatLogError).
var (
	errLogFileNotConfigured = errors.New("log file path is empty, configure log.file_path in config.json")
	errNoTerminalEmulator   = errors.New("no supported terminal emulator found")
)

// termCmdStyle describes how a terminal emulator is told which command to run.
type termCmdStyle int

const (
	// termStyleArgs appends the command as separate arguments,
	// e.g. `alacritty -e tail -n 50 -f /path/to/easyss.log`.
	termStyleArgs termCmdStyle = iota
	// termStyleString appends the command as one shell string,
	// e.g. `xfce4-terminal --command "tail -n 50 -f '/path/to/easyss.log'"`.
	termStyleString
)

// termLauncher is one entry of the terminal emulator table.
type termLauncher struct {
	bin   string
	args  []string
	style termCmdStyle
}

// termLaunchers is the ordered terminal emulator preference list, used when
// $TERMINAL does not name a usable terminal. The order puts the XDG default
// terminal launcher and the Wayland-native terminals first: on a modern
// Wayland session (Hyprland, sway, ...) none of the X11 era terminals below
// them is installed.
var termLaunchers = []termLauncher{
	// Default Terminal Execution Specification (Arch, Omarchy, ...).
	{"xdg-terminal-exec", []string{"--"}, termStyleArgs},
	{"foot", []string{"-e"}, termStyleArgs},
	{"alacritty", []string{"-e"}, termStyleArgs},
	// kitty takes the program to run without a separating flag.
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

// lookPath is exec.LookPath, kept in a variable so that tests can resolve the
// table against a simulated set of installed terminals.
var lookPath = exec.LookPath

// openWithDefaultApp opens a file in the desktop's default application. It is
// a variable so that tests can exercise the fallback without spawning a GUI
// window.
var openWithDefaultApp = func(path string) error {
	argv := sessionLaunch([]string{"xdg-open", path})

	return util.StartDetached(argv)
}

// openLogFile opens the log file for the user: in a terminal emulator tailing
// it, or — when no terminal emulator is available — as a snapshot in the
// desktop's default application.
//
// fallback reports that the snapshot path was taken, so the caller can tell
// the user why the log is not live.
func openLogFile(filePath string) (fallback bool, err error) {
	if strings.TrimSpace(filePath) == "" {
		return false, errLogFileNotConfigured
	}

	// A log file that does not exist yet would only make the terminal flash
	// and close again, so it is reported instead.
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

// openLogFileLinux tails the log in a terminal emulator. When no terminal
// emulator can be found it falls back to the snapshot viewer, so that the
// menu entry still shows something on a minimal desktop.
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

// logViewerArgv returns the command that tails filePath in a terminal
// emulator: $TERMINAL when it is usable, otherwise the first installed entry
// of termLaunchers.
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

// terminalFromEnv resolves the terminal named by $TERMINAL. A known terminal
// keeps the argument style of its table entry (extra words after the binary
// name are dropped, as they would land after the command separator); an
// unknown one is passed the command with the xterm style -e convention.
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

// launcherArgv builds the full argv for one terminal emulator.
func launcherArgv(bin string, l termLauncher, viewer []string) []string {
	argv := make([]string, 0, 1+len(l.args)+len(viewer))
	argv = append(argv, bin)
	argv = append(argv, l.args...)
	if l.style == termStyleString {
		return append(argv, util.ShellJoin(viewer))
	}

	return append(argv, viewer...)
}

// sessionLaunch hands the command to the desktop user when easyss runs as
// root (pkexec/sudo elevation, e.g. with TUN enabled), together with the
// session environment the elevation dropped. Without XDG_RUNTIME_DIR a
// Wayland terminal cannot reach the compositor at all. The command is
// returned unchanged when the user cannot be determined.
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

// openLogSnapshot writes the last logSnapshotLines lines of the log to a
// temporary file and opens it in the desktop's default application. It is the
// last resort when no terminal emulator is available.
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
	// The tray may run as root, while the application opening the snapshot
	// runs as the desktop user.
	if err := os.Chmod(f.Name(), 0o644); err != nil {
		return fmt.Errorf("chmod log snapshot: %w", err)
	}

	if err := openWithDefaultApp(f.Name()); err != nil {
		return fmt.Errorf("open %s: %w", f.Name(), err)
	}
	log.Info("[SYSTRAY] log snapshot opened", "file", f.Name())

	return nil
}
