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

	other := errors.New("boom")
	if msg := friendlyStartupError(other); msg != "服务启动失败：boom" {
		t.Fatalf("unexpected generic startup message: %q", msg)
	}
}
