package log

import (
	"bytes"
	"log/slog"
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