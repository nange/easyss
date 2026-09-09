package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
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
