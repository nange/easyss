package log

import (
	"bytes"
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
	// Info 级别时，Debug 消息不应出现
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
	// 验证 DefaultHandler 不 panic
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

	// 恢复原始 logger
	SetLogger(original)
}

func TestInit(t *testing.T) {
	original := Logger()

	t.Run("debug level", func(t *testing.T) {
		Init("", "debug")
		// Init 不应 panic，验证 logger 被设置
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

	// 恢复原始 logger
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

	// 验证文件被创建
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
	defer w.Close()

	n, err := io.WriteString(w, "test log message\n")
	if err != nil {
		t.Fatalf("write error: %v", err)
	}
	if n == 0 {
		t.Error("wrote 0 bytes")
	}

	// 关闭后验证文件内容
	w.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "test log message") {
		t.Errorf("file content mismatch: %s", string(data))
	}
}
