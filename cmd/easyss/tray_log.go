//go:build !headless

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
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

	return startDetached(argv)
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
		return false, startDetached(argv)
	case "darwin":
		argv := []string{"osascript",
			"-e", fmt.Sprintf(`tell application "Terminal" to do script "tail -f \"%s\""`, filePath),
			"-e", `tell application "Terminal" to activate`}
		return false, startDetached(argv)
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
		startErr := startDetached(argv)
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
		return append(argv, shellJoin(viewer))
	}

	return append(argv, viewer...)
}

// shellJoin quotes every argument so that the result can be handed to a
// terminal emulator that expects one shell command string.
func shellJoin(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}

	return strings.Join(quoted, " ")
}

// shellQuote quotes a single argument for the shell. Arguments without any
// character the shell treats specially are left untouched.
func shellQuote(s string) string {
	const specials = " \t\n\"'\\$`&|;<>()*?[]{}~#!"

	if s != "" && !strings.ContainsAny(s, specials) {
		return s
	}

	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// startDetached starts a command and returns as soon as it has been spawned:
// an interactive terminal stays in the foreground for as long as the user
// keeps the window open, so waiting for it — as util.Command does — would
// block the caller for the whole session. The process is reaped in the
// background to avoid leaving a zombie behind.
func startDetached(argv []string) error {
	if len(argv) == 0 {
		return errors.New("empty command")
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()

	return nil
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

	username, uid, ok := sessionUser()
	if !ok {
		log.Warn("[SYSTRAY] cannot determine the desktop user, launching as root")
		return argv
	}

	launch := []string{"runuser", "-u", username, "--", "env"}
	launch = append(launch, sessionEnv(username, uid)...)

	return append(launch, argv...)
}

// sessionUser returns the desktop user that invoked the elevated easyss:
// pkexec exports PKEXEC_UID, sudo exports SUDO_UID/SUDO_USER.
func sessionUser() (username string, uid int, ok bool) {
	candidates := []struct{ uid, name string }{
		{os.Getenv("PKEXEC_UID"), ""},
		{os.Getenv("SUDO_UID"), os.Getenv("SUDO_USER")},
	}

	for _, candidate := range candidates {
		if candidate.uid == "" {
			continue
		}
		id, err := strconv.Atoi(candidate.uid)
		if err != nil {
			continue
		}
		name := candidate.name
		if u, err := user.LookupId(candidate.uid); err == nil {
			name = u.Username
		}
		if name != "" {
			return name, id, true
		}
	}

	if name := os.Getenv("SUDO_USER"); name != "" {
		if u, err := user.Lookup(name); err == nil {
			if id, err := strconv.Atoi(u.Uid); err == nil {
				return u.Username, id, true
			}
		}
	}

	return "", 0, false
}

// sessionEnv builds the KEY=VALUE assignments of the desktop session, using
// the standard locations under /run/user/<uid> for anything the elevated
// process did not inherit.
func sessionEnv(username string, uid int) []string {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = fmt.Sprintf("/run/user/%d", uid)
	}

	home := ""
	if u, err := user.Lookup(username); err == nil {
		home = u.HomeDir
	}
	if home == "" {
		home = os.Getenv("HOME")
	}

	env := []string{"XDG_RUNTIME_DIR=" + runtimeDir}
	if home != "" {
		env = append(env, "HOME="+home)
	}

	waylandDisplay := os.Getenv("WAYLAND_DISPLAY")
	if waylandDisplay == "" {
		waylandDisplay = firstWaylandDisplay(runtimeDir)
	}
	if waylandDisplay != "" {
		env = append(env, "WAYLAND_DISPLAY="+waylandDisplay)
	}

	dbusAddr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if dbusAddr == "" {
		busPath := filepath.Join(runtimeDir, "bus")
		if _, err := os.Stat(busPath); err == nil {
			dbusAddr = "unix:path=" + busPath
		}
	}
	if dbusAddr != "" {
		env = append(env, "DBUS_SESSION_BUS_ADDRESS="+dbusAddr)
	}

	if xauthority := os.Getenv("XAUTHORITY"); xauthority != "" {
		env = append(env, "XAUTHORITY="+xauthority)
	} else if home != "" {
		xauthority = filepath.Join(home, ".Xauthority")
		if _, err := os.Stat(xauthority); err == nil {
			env = append(env, "XAUTHORITY="+xauthority)
		}
	}

	for _, key := range []string{"DISPLAY", "TERMINAL", "XDG_CURRENT_DESKTOP", "HYPRLAND_INSTANCE_SIGNATURE"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}

	return env
}

// firstWaylandDisplay returns the name of the first Wayland socket in the
// runtime directory, i.e. the WAYLAND_DISPLAY value a session would use.
func firstWaylandDisplay(runtimeDir string) string {
	matches, err := filepath.Glob(filepath.Join(runtimeDir, "wayland-*"))
	if err != nil {
		return ""
	}

	for _, match := range matches {
		if info, err := os.Stat(match); err == nil && info.Mode()&os.ModeSocket != 0 {
			return filepath.Base(match)
		}
	}

	return ""
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
