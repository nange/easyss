//go:build windows

package main

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// addrInUseTestErr 返回当前平台 net 包真实会包装的“端口占用”错误：Windows 是
// WSAEADDRINUSE（10048），不是 syscall.EADDRINUSE。
func addrInUseTestErr() error { return fmt.Errorf("bind: %w", windows.WSAEADDRINUSE) }

// TestIsAddrInUseWindowsWSA 固定 Windows 的 net 错误形态。
func TestIsAddrInUseWindowsWSA(t *testing.T) {
	if !isAddrInUse(addrInUseTestErr()) {
		t.Fatal("WSAEADDRINUSE must be classified as an in-use bind failure")
	}
}
