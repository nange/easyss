//go:build !darwin && !linux && !windows

package util

import "fmt"

func SetSysDNS(v []string) error {
	return nil
}

func SysDNS() ([]string, error) {
	return nil, nil
}

// SysDNSViaOSAScript 在非 darwin 平台上不受支持，调用会返回错误。
func SysDNSViaOSAScript() ([]string, error) {
	return nil, fmt.Errorf("SysDNSViaOSAScript is only supported on macOS")
}

// SetSysDNSViaOSAScript 在非 darwin 平台上不受支持，调用会返回错误。
func SetSysDNSViaOSAScript(servers []string) error {
	return fmt.Errorf("SetSysDNSViaOSAScript is only supported on macOS")
}
