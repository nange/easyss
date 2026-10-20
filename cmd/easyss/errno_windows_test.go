//go:build windows

package main

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// TestIsAddrInUseWindowsWSA 固定 Windows 的 net 错误形态：它包装的是
// WSAEADDRINUSE（10048），而不是 Unix 的 EADDRINUSE 应用错误码。
func TestIsAddrInUseWindowsWSA(t *testing.T) {
	if !isAddrInUse(fmt.Errorf("bind: %w", windows.WSAEADDRINUSE)) {
		t.Fatal("WSAEADDRINUSE must be classified as an in-use bind failure")
	}
}
