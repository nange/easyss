package util

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// maxUnixSocketPath is the shortest sun_path budget Go's net package builds
// against: 104 bytes on macOS/BSD (Linux allows 108). Staying under it is what
// lets the same socket test pass on every platform.
const maxUnixSocketPath = 104

// waylandRuntimeDir returns a short directory to act as the session runtime
// directory, optionally with a live wayland-0 socket in it. The sun_path of a
// Unix socket is limited to about 104 bytes, and t.TempDir() embeds the test
// name, which is long enough to exceed that limit on macOS and Windows — the
// bind then fails with "invalid argument", not with anything that names the
// real cause.
func waylandRuntimeDir(t *testing.T, withSocket bool) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "easyss-wl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "wayland-0")
	if len(socketPath) > maxUnixSocketPath {
		// Nothing about the code under test depends on the length, so a temp
		// root this deep is an environment limit, not a failure.
		t.Skipf("temp root leaves no sun_path budget: %d bytes for %s", len(socketPath), socketPath)
	}

	if withSocket {
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen on %s: %v", socketPath, err)
		}
		t.Cleanup(func() { ln.Close() }) //nolint:errcheck

		// Test premise: a Unix listener really is a socket, so the ModeSocket
		// check in firstWaylandDisplay is what accepts it (not the name).
		info, err := os.Stat(socketPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSocket == 0 {
			t.Fatalf("%s is not a socket: mode %v", socketPath, info.Mode())
		}
	}

	return dir
}

func TestFirstWaylandDisplay(t *testing.T) {
	t.Run("运行目录不存在", func(t *testing.T) {
		if got := firstWaylandDisplay(filepath.Join(waylandRuntimeDir(t, false), "missing")); got != "" {
			t.Errorf("firstWaylandDisplay = %q, want empty", got)
		}
	})

	t.Run("没有 wayland socket", func(t *testing.T) {
		dir := waylandRuntimeDir(t, false)
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
		if got, want := firstWaylandDisplay(waylandRuntimeDir(t, true)), "wayland-0"; got != want {
			t.Errorf("firstWaylandDisplay = %q, want %q", got, want)
		}
	})

	// The helper is only ever called with a GLOB pattern that cannot fail
	// (filepath.Join of a directory and "wayland-*"), so the ErrBadPattern
	// branch has no reachable input to test.
}
