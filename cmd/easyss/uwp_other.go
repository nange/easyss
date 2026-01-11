//go:build !windows && !without_tray

package main

func (st *SysTray) AddUWPLoopbackMenu() {
	// No-op on non-Windows
}
