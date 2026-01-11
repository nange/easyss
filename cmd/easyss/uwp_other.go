//go:build !windows

package main

func (st *SysTray) AddUWPLoopbackMenu() {
	// No-op on non-Windows
}
