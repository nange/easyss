//go:build !windows

package tun

func ensureWintun() error {
	return nil
}
