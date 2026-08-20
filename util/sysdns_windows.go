//go:build windows

package util

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
