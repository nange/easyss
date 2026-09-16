package util

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// SessionUser returns the desktop user that invoked the elevated easyss:
// pkexec exports PKEXEC_UID, sudo exports SUDO_UID/SUDO_USER.
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

// SessionEnv builds the KEY=VALUE assignments of the desktop session, using
// the standard locations under /run/user/<uid> for anything the elevated
// process did not inherit.
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
