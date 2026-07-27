//go:build windows

package main

import (
	"fmt"

	"github.com/nange/easyss/v3/client/tun"
)

func IsRoot() bool {
	return true
}

func RunMeElevated(extraArgs ...string) error {
	return nil
}

// SpawnTunHelper is only supported on macOS.
func SpawnTunHelper(dev tun.DeviceConfig, dnsServer string) (*tunHelperResult, error) {
	return nil, fmt.Errorf("SpawnTunHelper is only supported on macOS")
}
