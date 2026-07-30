//go:build !darwin && !linux

package util

import "fmt"

func SetSysDNS(v []string) error {
	return nil
}

func SysDNS() ([]string, error) {
	return nil, nil
}

// SysDNSViaOSAScript is a no-op on non-darwin platforms.
func SysDNSViaOSAScript() ([]string, error) {
	return nil, fmt.Errorf("SysDNSViaOSAScript is only supported on macOS")
}

// SetSysDNSViaOSAScript is a no-op on non-darwin platforms.
func SetSysDNSViaOSAScript(servers []string) error {
	return fmt.Errorf("SetSysDNSViaOSAScript is only supported on macOS")
}
