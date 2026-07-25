//go:build !darwin

package main

import (
	"fmt"
	"os"

	"github.com/nange/easyss/v3/client/config"
)

// runTunOnly is only implemented on Darwin.
func runTunOnly(_ *config.ClientConfig, _ string) {
	fmt.Fprintln(os.Stderr, "tun-only mode is only supported on macOS")
	os.Exit(1)
}

const tunKeepaliveFile = ""

func writeTunKeepalive() error  { return nil }
func removeTunKeepalive() error { return nil }
