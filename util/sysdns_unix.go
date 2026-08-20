//go:build !darwin && !windows

package util

// SetSysDNS is a no-op on this platform.
func SetSysDNS(v []string) error {
	return nil
}

// SysDNS returns the dns servers of the system, parsed from /etc/resolv.conf.
func SysDNS() ([]string, error) {
	return sysDNSServersFromResolvConf("/etc/resolv.conf")
}
