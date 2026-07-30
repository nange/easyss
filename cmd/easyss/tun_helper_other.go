//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"
)

// runTunHelper is a no-op on non-darwin platforms.
func runTunHelper(httpAddr, fdSocketPath, logFilePath, logLevel string) int {
	fmt.Fprintln(os.Stderr, "tun helper is only supported on macOS")
	return 1
}
