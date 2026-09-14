package main

import (
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/tun"
)

// failedTunManager builds a manager whose Start() fails immediately, so the
// engine failure path can be exercised without root and without touching a
// real TUN device: an unparsable log level is rejected by the engine's
// general() step before any device is opened.
func failedTunManager() *tun.Manager {
	return tun.New(tun.Config{LogLevel: "not-a-log-level"})
}

// TestStartTunEngineReportsFailureToHook pins the contract the tray relies on:
// a failed engine start must reach tunStartFailureHook, which reverts the menu
// item and tears down the elevated helper. Without it the menu keeps claiming
// TUN is on while nothing is routed through it.
func TestStartTunEngineReportsFailureToHook(t *testing.T) {
	orig := tunStartFailureHook
	t.Cleanup(func() { tunStartFailureHook = orig })

	called := make(chan struct{}, 1)
	tunStartFailureHook = func() { called <- struct{}{} }

	startTunEngine(failedTunManager(), "device")

	select {
	case <-called:
	case <-time.After(30 * time.Second):
		t.Fatal("tunStartFailureHook was not called after the engine failed to start")
	}
}
