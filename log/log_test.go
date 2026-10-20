package log

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogOutput(t *testing.T) {
	var buf bytes.Buffer
	handler := TextHandler(&buf, slog.LevelDebug)
	logger := slog.New(handler)
	SetLogger(logger)

	Info("test message")

	output := buf.String()
	if !strings.Contains(output, "source=") || !strings.Contains(output, "log_test.go") {
		t.Errorf("log output should contain file name, but not found. output: %s", output)
	}
}

func TestLogLevels(t *testing.T) {
	tests := []struct {
		name  string
		level slog.Level
		fn    func(string, ...any)
		msg   string
	}{
		{"Debug", slog.LevelDebug, Debug, "debug message"},
		{"Info", slog.LevelInfo, Info, "info message"},
		{"Warn", slog.LevelWarn, Warn, "warn message"},
		{"Error", slog.LevelError, Error, "error message"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := TextHandler(&buf, slog.LevelDebug)
			SetLogger(slog.New(handler))

			tt.fn(tt.msg)
			output := buf.String()

			if !strings.Contains(output, tt.msg) {
				t.Errorf("expected message %q in output, got: %s", tt.msg, output)
			}
			if !strings.Contains(output, strings.ToUpper(tt.name)) {
				t.Errorf("expected level %q in output, got: %s", strings.ToUpper(tt.name), output)
			}
		})
	}
}

func TestLogLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	handler := TextHandler(&buf, slog.LevelInfo)
	SetLogger(slog.New(handler))

	Debug("should not appear")
	Info("should appear")

	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Error("Debug message should be filtered at Info level")
	}
	if !strings.Contains(output, "should appear") {
		t.Error("Info message should appear")
	}
}

func TestTextHandler(t *testing.T) {
	var buf bytes.Buffer
	handler := TextHandler(&buf, slog.LevelInfo)
	l := slog.New(handler)
	l.Info("hello", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "msg=hello") {
		t.Errorf("expected msg=hello, got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("expected key=value, got: %s", output)
	}
}

func TestJSONHandler(t *testing.T) {
	var buf bytes.Buffer
	handler := JSONHandler(&buf, slog.LevelInfo)
	l := slog.New(handler)
	l.Info("hello", "key", "value")

	output := buf.String()
	var m map[string]any
	if err := json.Unmarshal([]byte(output), &m); err != nil {
		t.Fatalf("invalid JSON output: %v, output: %s", err, output)
	}
	if m["msg"] != "hello" {
		t.Errorf("msg = %v", m["msg"])
	}
	if m["key"] != "value" {
		t.Errorf("key = %v", m["key"])
	}
}

func TestDefaultHandler(t *testing.T) {
	handler := DefaultHandler(slog.LevelInfo)
	if handler == nil {
		t.Error("DefaultHandler returned nil")
	}
}

func TestSetLoggerAndLogger(t *testing.T) {
	original := Logger()

	var buf bytes.Buffer
	newLogger := slog.New(TextHandler(&buf, slog.LevelDebug))
	SetLogger(newLogger)

	if Logger() != newLogger {
		t.Error("Logger() should return the newly set logger")
	}

	SetLogger(original)
}

func TestInit(t *testing.T) {
	original := Logger()

	t.Run("debug level", func(t *testing.T) {
		Init("", "debug")
		if Logger() == nil {
			t.Error("logger is nil after Init")
		}
	})

	t.Run("warn level", func(t *testing.T) {
		Init("", "warn")
		if Logger() == nil {
			t.Error("logger is nil after Init")
		}
	})

	t.Run("error level", func(t *testing.T) {
		Init("", "error")
		if Logger() == nil {
			t.Error("logger is nil after Init")
		}
	})

	t.Run("默认 info level", func(t *testing.T) {
		Init("", "")
		if Logger() == nil {
			t.Error("logger is nil after Init")
		}
	})

	SetLogger(original)
}

func TestInit_WithFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	original := Logger()

	Init(logPath, "info")

	if Logger() == nil {
		t.Error("logger is nil after Init with file")
	}

	if _, err := os.Stat(logPath); err != nil {
		t.Logf("log file not found (may have delayed creation): %v", err)
	}

	SetLogger(original)
}

func TestFileWriter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	w := FileWriter(logPath)
	if w == nil {
		t.Fatal("FileWriter returned nil")
	}
	defer w.Close() //nolint:errcheck

	n, err := io.WriteString(w, "test log message\n")
	if err != nil {
		t.Fatalf("write error: %v", err)
	}
	if n == 0 {
		t.Error("wrote 0 bytes")
	}

	w.Close() //nolint:errcheck

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "test log message") {
		t.Errorf("file content mismatch: %s", string(data))
	}
}

// TestCloseFileOutput 固定句柄由 Init 登记、由 CloseFileOutput 释放，不能只等 GC：被打开的文件
// 在 Windows 上无法删除，Android 在 Stop 后清理/轮转日志也会被遗留句柄挡住。
func TestCloseFileOutput(t *testing.T) {
	original := Logger()
	defer SetLogger(original)

	logPath := filepath.Join(t.TempDir(), "close.log")

	Init(logPath, "debug")
	t.Cleanup(func() {
		// 兜底释放：否则 Windows 上的临时目录清理会再失败一次，把断言失败变成误导性的清理错误。
		_ = CloseFileOutput()
	})

	// 必须触发一次写入：未写入时 lumberjack 不创建文件，也就没有句柄。
	Info("before close")

	fileOutputMu.Lock()
	tracked := fileOutput
	fileOutputMu.Unlock()
	if tracked == nil {
		t.Fatal("Init did not register the file output")
	}

	if err := CloseFileOutput(); err != nil {
		t.Fatalf("CloseFileOutput: %v", err)
	}

	fileOutputMu.Lock()
	still := fileOutput
	fileOutputMu.Unlock()
	if still != nil {
		t.Error("CloseFileOutput kept the file output registered")
	}

	if err := CloseFileOutput(); err != nil {
		t.Errorf("second CloseFileOutput: %v", err)
	}

	// 释放只改目的地不改级别，释放后继续写日志也不应 panic。
	if !Logger().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("closing the file output should keep the configured level")
	}
	Info("after close")

	Init(logPath, "info")
	Info("reopened")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file after re-init: %v", err)
	}
	if !strings.Contains(string(data), "reopened") {
		t.Errorf("Init after CloseFileOutput should reopen the file, content: %q", data)
	}
}

// TestCloseFileOutputIsTerminalForStaleLoggers 固定迟到的写入不能复活句柄：换掉包级 logger 只挡住之后
// 才 Load 的写入，先拿到旧 logger 的后台 goroutine 仍会在 Close 之后写，而 lumberjack 发现句柄为 nil
// 会重新打开文件，Windows 上的删除/重命名因此被挡住。
func TestCloseFileOutputIsTerminalForStaleLoggers(t *testing.T) {
	original := Logger()
	defer SetLogger(original)

	logPath := filepath.Join(t.TempDir(), "stale.log")

	Init(logPath, "debug")
	// 模拟在 CloseFileOutput 之前就拿到旧 logger 的后台 goroutine。
	stale := Logger()

	Info("before close")
	if err := CloseFileOutput(); err != nil {
		t.Fatalf("CloseFileOutput: %v", err)
	}

	if err := os.Remove(logPath); err != nil {
		t.Fatalf("remove log file: %v", err)
	}
	stale.Info("late write through the stale logger")

	if _, err := os.Stat(logPath); err == nil {
		t.Error("a late write through a stale logger re-created the log file")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat log file: %v", err)
	}
}
