//go:build !linux

package util

import "slices"

// SetSysDNSForTun configures DNS resolution for TUN mode. Platforms other than
// Linux keep their DNS configuration at the network-service or connection level
// (networksetup on macOS, the registry on Windows) and resolve through the
// routing table, so the TUN routes carry the lookups into the tunnel without
// any per-link resolver state: the plain system DNS is all that is needed.
func SetSysDNSForTun(_ string, v []string) error {
	return SetSysDNS(v)
}

// EnsureSysDNSForTun reports nothing to re-assert on these platforms.
func EnsureSysDNSForTun(_ string, _ []string) error {
	return nil
}

// RestoreSysDNSForTun restores the servers captured before TUN started.
func RestoreSysDNSForTun(_ string, origin []string) error {
	if len(origin) == 0 {
		return SetSysDNS([]string{"empty"})
	}

	curr, err := SysDNS()
	if err != nil {
		return err
	}
	if slices.Equal(curr, origin) {
		return nil
	}
	return SetSysDNS(origin)
}
