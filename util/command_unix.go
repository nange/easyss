//go:build !windows

package util

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func Command(name string, arg ...string) (string, error) {
	return CommandContext(context.Background(), name, arg...)
}

// CommandContext runs the command and returns its trimmed stdout. A failed
// command yields an empty string, so callers that need the output of a command
// that may fail have to use CommandContextCombined instead.
func CommandContext(ctx context.Context, name string, arg ...string) (string, error) {
	out, err := CommandContextCombined(ctx, name, arg...)
	if err != nil {
		return "", err
	}
	return out, nil
}

// CommandContextCombined is CommandContext that also returns what the command
// printed on failure: the TUN platform scripts report their failing step on
// stderr, and "exit status 1" alone would hide it from the user notification.
func CommandContextCombined(ctx context.Context, name string, arg ...string) (string, error) {
	c := exec.CommandContext(ctx, name, arg...)
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%q: %w: %q", strings.Join(append([]string{name}, arg...), " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}
