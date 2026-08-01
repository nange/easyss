//go:build !windows && !linux && !darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func IsRoot() bool {
	return true // Assume root or bypass check for unsupported OS
}

func RunMeElevated(extraArgs ...string) error {
	return errors.New("unsupported operating system for elevation")
}

func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	return nil, nil, fmt.Errorf("SpawnTunHelper is not supported on this platform")
}
