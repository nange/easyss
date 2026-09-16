package util

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestFirstWaylandDisplay(t *testing.T) {
	t.Run("运行目录不存在", func(t *testing.T) {
		if got := firstWaylandDisplay(filepath.Join(t.TempDir(), "missing")); got != "" {
			t.Errorf("firstWaylandDisplay = %q, want empty", got)
		}
	})

	t.Run("没有 wayland socket", func(t *testing.T) {
		dir := t.TempDir()
		// A non-matching entry and a matching name that is not a socket: only
		// an actual socket may be reported, otherwise a stale lock file named
		// wayland-0 would be handed to the tray as WAYLAND_DISPLAY.
		if err := os.WriteFile(filepath.Join(dir, "bus"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "wayland-0"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := firstWaylandDisplay(dir); got != "" {
			t.Errorf("firstWaylandDisplay = %q, want empty", got)
		}
	})

	t.Run("返回第一个 wayland socket", func(t *testing.T) {
		dir := t.TempDir()
		socketPath := filepath.Join(dir, "wayland-0")
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen on %s: %v", socketPath, err)
		}
		defer ln.Close() //nolint:errcheck

		// Test premise: a Unix listener really is a socket, so the ModeSocket
		// check in firstWaylandDisplay is what accepts it (not the name).
		info, err := os.Stat(socketPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSocket == 0 {
			t.Fatalf("%s is not a socket: mode %v", socketPath, info.Mode())
		}

		if got, want := firstWaylandDisplay(dir), "wayland-0"; got != want {
			t.Errorf("firstWaylandDisplay = %q, want %q", got, want)
		}
	})

	// The helper is only ever called with a GLOB pattern that cannot fail
	// (filepath.Join of a directory and "wayland-*"), so the ErrBadPattern
	// branch has no reachable input to test.
}
