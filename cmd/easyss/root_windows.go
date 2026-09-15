//go:build windows

package main

import (
	"fmt"
	"io"
	"net"
	"time"
)

func IsRoot() bool {
	return true
}

func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	return nil, nil, fmt.Errorf("SpawnTunHelper is not supported on this platform")
}
