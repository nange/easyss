package util

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// SessionUser 返回调用提权后 easyss 的桌面用户：
// pkexec 导出 PKEXEC_UID，sudo 导出 SUDO_UID/SUDO_USER。
func SessionUser() (username string, uid int, ok bool) {
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

// SessionEnv 构建桌面会话的 KEY=VALUE 环境变量列表，对于提权进程
// 未继承的内容，使用 /run/user/<uid> 下的标准位置。
func SessionEnv(username string, uid int) []string {
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

// firstWaylandDisplay 返回运行时目录中第一个 Wayland socket 的名称，
// 即会话会使用的 WAYLAND_DISPLAY 值。
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
