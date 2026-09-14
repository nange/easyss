//go:build !headless

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestFriendlyConfigError(t *testing.T) {
	var v any
	err := json.Unmarshal([]byte(`{"servers": [`), &v)
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Fatalf("expected *json.SyntaxError, got %T", err)
	}
	if got := friendlyConfigError(syntaxErr); got != "JSON配置文件解析失败："+syntaxErr.Error() {
		t.Fatalf("unexpected JSON error message: %q", got)
	}

	var mm map[string]int
	err = json.Unmarshal([]byte(`{"timeout": "abc"}`), &mm)
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("expected *json.UnmarshalTypeError, got %T", err)
	}
	if got := friendlyConfigError(typeErr); got != "JSON配置文件解析失败："+typeErr.Error() {
		t.Fatalf("unexpected JSON type error message: %q", got)
	}

	if got := friendlyConfigError(fs.ErrNotExist); got != "配置文件不存在："+fs.ErrNotExist.Error() {
		t.Fatalf("unexpected not-exist message: %q", got)
	}

	if got := friendlyConfigError(errors.New("server is required")); got != "配置文件加载失败：server is required" {
		t.Fatalf("unexpected generic message: %q", got)
	}
}

func TestFriendlyStartupError(t *testing.T) {
	// Unix: errno-based detection.
	msg := friendlyStartupError(syscall.EADDRINUSE)
	if !strings.Contains(msg, "本地端口可能被占用") {
		t.Fatalf("EADDRINUSE should get the port-in-use hint: %q", msg)
	}

	// Windows: the canonical message text.
	windowsErr := errors.New("bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.")
	if msg := friendlyStartupError(windowsErr); !strings.Contains(msg, "本地端口可能被占用") {
		t.Fatalf("windows in-use error should get the hint: %q", msg)
	}

	// Empty password (crypto.DeriveMasterKey).
	passwordErr := errors.New("crypto: password is empty")
	if msg := friendlyStartupError(passwordErr); !strings.Contains(msg, "服务器密码为空") {
		t.Fatalf("empty-password error should get the config hint: %q", msg)
	}

	// HTTP proxy without socks_port (runner.errSocksRequired).
	socksRequiredErr := errors.New("http proxy requires socks_port to be enabled")
	if msg := friendlyStartupError(socksRequiredErr); !strings.Contains(msg, "socks_port 需大于 0") {
		t.Fatalf("socks-required error should get the config hint: %q", msg)
	}

	// Server domain failed to resolve (runner.resolveServerDomain): fatal.
	dnsErr := errors.New("server domain proxy.example.com resolution failed: dns boom")
	if msg := friendlyStartupError(dnsErr); !strings.Contains(msg, "服务端域名解析失败") {
		t.Fatalf("resolution error should get the dns hint: %q", msg)
	}

	other := errors.New("boom")
	if msg := friendlyStartupError(other); msg != "服务启动失败：boom" {
		t.Fatalf("unexpected generic startup message: %q", msg)
	}
}

func TestFriendlyStartupWarning(t *testing.T) {
	// Non-fatal startup warnings (e.g. a custom rule file that failed to
	// load) keep the "启动警告" prefix and the detail.
	msg := friendlyStartupWarning(errors.New("load custom rule file: open direct.txt: no such file or directory"))
	if msg != "启动警告：load custom rule file: open direct.txt: no such file or directory" {
		t.Fatalf("unexpected startup warning message: %q", msg)
	}
}

func TestFriendlyTunError(t *testing.T) {
	// A start cancelled by Stop() (toggle off, server switch, app exit) is
	// not a failure: nothing may be shown, or every TUN toggle-off would pop
	// a notification.
	if msg := friendlyTunError(context.Canceled); msg != "" {
		t.Fatalf("context.Canceled must not notify, got %q", msg)
	}
	if msg := friendlyTunError(fmt.Errorf("tun: start engine: %w", context.Canceled)); msg != "" {
		t.Fatalf("a wrapped context.Canceled must not notify, got %q", msg)
	}
	if msg := friendlyTunError(nil); msg != "" {
		t.Fatalf("nil error must not notify, got %q", msg)
	}

	// The user cancelled the pkexec/osascript auth dialog: the platform
	// wrappers emit these fixed literals, and this is user intent, not a
	// fault, so it stays silent too.
	cancelled := errors.New("pkexec exited before tun helper started: exit status 126: Error executing command as another user: Request dismissed")
	if msg := friendlyTunError(cancelled); msg != "" {
		t.Fatalf("a cancelled auth dialog must not notify, got %q", msg)
	}
	osascript := errors.New("osascript exited before tun helper started: exit status 1: User canceled.")
	if msg := friendlyTunError(osascript); msg != "" {
		t.Fatalf("a cancelled admin dialog must not notify, got %q", msg)
	}

	// Missing privileges keep the actionable hint.
	denied := errors.New("tun2socks requires root on this platform")
	if msg := friendlyTunError(denied); !strings.Contains(msg, "需要管理员权限") || !strings.Contains(msg, denied.Error()) {
		t.Fatalf("a permission failure should get the elevation hint: %q", msg)
	}
	perm := fmt.Errorf("tun: create device: open /dev/net/tun: %w", fs.ErrPermission)
	if msg := friendlyTunError(perm); !strings.Contains(msg, "需要管理员权限") {
		t.Fatalf("an fs.ErrPermission failure should get the elevation hint: %q", msg)
	}

	// Anything else names both the missing feature and the fact that the
	// proxy core still works, plus the underlying reason.
	engineErr := errors.New("tun: start engine: boom")
	msg := friendlyTunError(engineErr)
	for _, want := range []string{"Tun2socks 启动失败", "系统全局流量未生效", "代理（SOCKS5/HTTP）仍可正常使用", engineErr.Error()} {
		if !strings.Contains(msg, want) {
			t.Fatalf("generic TUN message %q is missing %q", msg, want)
		}
	}
}

func TestTrayStartTunFailureNotifies(t *testing.T) {
	origHook, origNotify, origText := tunStartFailureHook, tunStartNotify, tunStartErrorText
	t.Cleanup(func() {
		tunStartFailureHook, tunStartNotify, tunStartErrorText = origHook, origNotify, origText
	})

	var (
		reverted  int
		notified  []string
		notifyMu  sync.Mutex
		tunFailed = errors.New("tun: create device: boom")
	)
	tunStartFailureHook = func() { reverted++ }
	tunStartNotify = func(msg string) {
		notifyMu.Lock()
		defer notifyMu.Unlock()
		notified = append(notified, msg)
	}
	tunStartErrorText = friendlyTunError

	trayStartTunFailure(tunFailed)

	notifyMu.Lock()
	got := append([]string(nil), notified...)
	notifyMu.Unlock()
	if reverted != 1 {
		t.Fatalf("revert hook calls = %d, want 1", reverted)
	}
	if len(got) != 1 {
		t.Fatalf("notifications = %q, want exactly one", got)
	}
	if !strings.Contains(got[0], tunFailed.Error()) {
		t.Fatalf("notification %q should carry the underlying reason", got[0])
	}

	// A deliberate stop must still revert the state (the toggle-off path
	// relies on it) but must not notify.
	trayStartTunFailure(fmt.Errorf("tun: start engine: %w", context.Canceled))

	notifyMu.Lock()
	defer notifyMu.Unlock()
	if reverted != 2 {
		t.Fatalf("revert hook calls after a cancelled start = %d, want 2", reverted)
	}
	if len(notified) != 1 {
		t.Fatalf("a cancelled start notified %q, want no extra notification", notified[1:])
	}
}

// TestTrayStartTunFailureHeadlessText pins the fallback main.go keeps in builds
// without tray.go: with no tunStartErrorText installed, the raw error text is
// what would be notified.
func TestTrayStartTunFailureHeadlessText(t *testing.T) {
	origHook, origNotify, origText := tunStartFailureHook, tunStartNotify, tunStartErrorText
	t.Cleanup(func() {
		tunStartFailureHook, tunStartNotify, tunStartErrorText = origHook, origNotify, origText
	})

	raw := errors.New("tun: create device: boom")
	var notified []string
	tunStartFailureHook = nil
	tunStartNotify = func(msg string) { notified = append(notified, msg) }
	tunStartErrorText = nil

	trayStartTunFailure(raw)

	if len(notified) != 1 || notified[0] != raw.Error() {
		t.Fatalf("headless fallback notified %q, want [%q]", notified, raw.Error())
	}
}
