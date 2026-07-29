//go:build windows

package main

import (
	"fmt"
	"io"
	"net"
)

func IsRoot() bool {
	return true
}

func RunMeElevated(extraArgs ...string) error {
	return nil
}

// SpawnTunHelper is only supported on macOS.
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string) (io.WriteCloser, net.Listener, error) {
	return nil, nil, fmt.Errorf("SpawnTunHelper is only supported on macOS")
}

// ReceiveFd is only supported on macOS.
func ReceiveFd(listener net.Listener) (int, error) {
	return -1, fmt.Errorf("ReceiveFd is only supported on macOS")
}
