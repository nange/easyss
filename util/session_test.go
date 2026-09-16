package util

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// maxUnixSocketPath 是 Go net 包所遵循的最短 sun_path 预算：
// macOS/BSD 上为 104 字节（Linux 允许 108）。保持在其之下，
// 才能让同一个 socket 测试在所有平台上通过。
const maxUnixSocketPath = 104

// waylandRuntimeDir 返回一个短目录作为会话运行时目录，可选地在其内
// 放置一个真实的 wayland-0 socket。Unix socket 的 sun_path 限制约为
// 104 字节，而 t.TempDir() 会嵌入测试名，长度足以在 macOS 和 Windows
// 上超过该限制——此时 bind 会以 "invalid argument" 失败，
// 而不是任何能指出真正原因的错误。
func waylandRuntimeDir(t *testing.T, withSocket bool) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "easyss-wl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "wayland-0")
	if len(socketPath) > maxUnixSocketPath {
		// 被测代码的任何部分都不依赖路径长度，因此临时根目录过深
		// 只是环境限制，不是测试失败。
		t.Skipf("temp root leaves no sun_path budget: %d bytes for %s", len(socketPath), socketPath)
	}

	if withSocket {
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen on %s: %v", socketPath, err)
		}
		t.Cleanup(func() { ln.Close() }) //nolint:errcheck

		// 测试前提：Unix listener 确实是 socket，因此 firstWaylandDisplay
		// 中基于 ModeSocket 的检查（而非名称）才会接受它。
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
		// 不匹配的条目，以及名称匹配但不是 socket 的文件：只有真正的
		// socket 才会被返回，否则名为 wayland-0 的过期锁文件会被当作
		// WAYLAND_DISPLAY 传给托盘。
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

	// 该辅助函数只会被传入不会失败的 GLOB 模式
	// （目录与 "wayland-*" 的 filepath.Join），因此 ErrBadPattern
	// 分支没有可达的输入可供测试。
}
