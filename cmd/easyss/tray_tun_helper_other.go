//go:build !darwin && !linux && !without_tray

package main

import "fmt"

// createTun2socksViaHelper is only supported on macOS.
func (a *TrayApp) createTun2socksViaHelper() error {
	return fmt.Errorf("createTun2socksViaHelper is only supported on macOS")
}
