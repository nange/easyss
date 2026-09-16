//go:build !headless && !darwin && !linux && !windows

package main

// tryAcquireSingletonLock is a no-op on platforms without a lock
// implementation: the app runs without single-instance protection, matching
// the other platform fallback files (root_fallback.go, autostart_other.go).
func tryAcquireSingletonLock() error { return nil }

// acquireSingletonLock is a no-op (see tryAcquireSingletonLock).
func acquireSingletonLock() {}

// releaseSingletonLock is a no-op (see tryAcquireSingletonLock).
func releaseSingletonLock() {}
