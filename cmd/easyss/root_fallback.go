//go:build !windows && !linux && !darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
)

func IsRoot() bool {
	return true // Assume root or bypass check for unsupported OS
}

func RunMeElevated(extraArgs ...string) error {
	return errors.New("unsupported operating system for elevation")
}

// SpawnTunHelper is only supported on macOS.
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string) (*exec.Cmd, io.WriteCloser, net.Listener, error) {
	return nil, nil, nil, fmt.Errorf("SpawnTunHelper is only supported on macOS")
}

// ReceiveFd is only supported on macOS.
func ReceiveFd(listener net.Listener) (int, error) {
	return -1, fmt.Errorf("ReceiveFd is only supported on macOS")
}
