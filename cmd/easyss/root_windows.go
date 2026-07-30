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

func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string) (io.WriteCloser, net.Listener, error) {
	return nil, nil, fmt.Errorf("SpawnTunHelper is not supported on this platform")
}
