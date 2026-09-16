//go:build !darwin && !linux

package main

import (
	"fmt"
	"io"
	"net"
	"time"
)

// IsRoot reports whether the process runs with administrator privileges. On
// platforms without the unix elevation flow, the check is bypassed (returns
// true) so the direct TUN path is used.
func IsRoot() bool {
	return true
}

// SpawnTunHelper is not supported on this platform: the elevated-helper flow
// exists only on darwin/linux.
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	return nil, nil, fmt.Errorf("SpawnTunHelper is not supported on this platform")
}
