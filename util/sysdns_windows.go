//go:build windows

package util

import "fmt"

// SetSysDNS is a no-op on this platform.
func SetSysDNS(v []string) error {
	return nil
}

// SysDNS returns the dns servers of the system, parsed from the output of `ipconfig /all`.
func SysDNS() ([]string, error) {
	out, err := Command("ipconfig", "/all")
	if err != nil {
		return nil, err
	}
	return parseDNSServersFromIPConfig(out), nil
}

// SysDNSViaOSAScript is a no-op on non-darwin platforms.
func SysDNSViaOSAScript() ([]string, error) {
	return nil, fmt.Errorf("SysDNSViaOSAScript is only supported on macOS")
}

// SetSysDNSViaOSAScript is a no-op on non-darwin platforms.
func SetSysDNSViaOSAScript(servers []string) error {
	return fmt.Errorf("SetSysDNSViaOSAScript is only supported on macOS")
}
