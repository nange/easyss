//go:build !windows && !linux && !darwin

package main

import (
	"errors"
	"fmt"

	"github.com/nange/easyss/v3/client/tun"
)

func IsRoot() bool {
	return true // Assume root or bypass check for unsupported OS
}

func RunMeElevated(extraArgs ...string) error {
	return errors.New("unsupported operating system for elevation")
}

// SpawnTunHelper is only supported on macOS.
func SpawnTunHelper(dev tun.DeviceConfig, dnsServer string) (*tunHelperResult, error) {
	return nil, fmt.Errorf("SpawnTunHelper is only supported on macOS")
}
