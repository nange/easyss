//go:build !darwin && !linux && !headless

package main

import "fmt"

// tunUpViaHelper 仅在 macOS/Linux 上受支持。
func (s *session) tunUpViaHelper() error {
	return fmt.Errorf("tunUpViaHelper is only supported on macOS and Linux")
}
