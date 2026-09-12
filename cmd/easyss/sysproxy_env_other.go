//go:build !linux && !headless

package main

// setSysProxyEnv is a no-op outside Linux: macOS and Windows have a real
// system-wide proxy configuration, which the sysproxy package already updates
// and which the browsers there actually honour.
func setSysProxyEnv(_ int) (bool, error) {
	return false, nil
}

func unsetSysProxyEnv() (bool, error) {
	return false, nil
}
