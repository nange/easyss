package util

import (
	"errors"
	"os/exec"
)

// StartDetached starts a command and returns as soon as it has been spawned:
// an interactive terminal stays in the foreground for as long as the user
// keeps the window open, so waiting for it — as Command does — would block
// the caller for the whole session. The process is reaped in the background
// to avoid leaving a zombie behind.
func StartDetached(argv []string) error {
	if len(argv) == 0 {
		return errors.New("empty command")
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()

	return nil
}
