//go:build !windows

package util

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func Command(name string, arg ...string) (string, error) {
	return CommandContext(context.Background(), name, arg...)
}

func CommandContext(ctx context.Context, name string, arg ...string) (string, error) {
	c := exec.CommandContext(ctx, name, arg...)
	out, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%q: %w: %q", strings.Join(append([]string{name}, arg...), " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func CommandWithoutProxy(name string, arg ...string) (string, error) {
	return CommandWithoutProxyContext(context.Background(), name, arg...)
}

func CommandWithoutProxyContext(ctx context.Context, name string, arg ...string) (string, error) {
	c := exec.CommandContext(ctx, name, arg...)
	c.Env = removeProxyEnv(os.Environ())
	out, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%q: %w: %q", strings.Join(append([]string{name}, arg...), " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}
