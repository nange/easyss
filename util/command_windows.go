package util

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// Command Ref: https://github.com/wzshiming/sysproxy/blob/5e86de4b71cf89f78bf95976d6ca35ea2e9ba526/command_windows.go#L10
func Command(name string, arg ...string) (string, error) {
	return CommandContext(context.Background(), name, arg...)
}

func CommandContext(ctx context.Context, name string, arg ...string) (string, error) {
	c := exec.CommandContext(ctx, name, arg...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%q: %w: %q", strings.Join(append([]string{name}, arg...), " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}
