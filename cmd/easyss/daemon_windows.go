//go:build windows

package main

func runDaemon() {
	// Daemon mode is not supported on Windows.
	// The caller in start.go already guards with runtime.GOOS != "windows".
}
