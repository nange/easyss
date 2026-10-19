//go:build darwin || linux

package tun

import "golang.org/x/sys/unix"

// closeRawDeviceFD 关闭一个裸 fd（仅 darwin/linux：fd 路径只在这两个平台上存在）。
func closeRawDeviceFD(fd int) error { return unix.Close(fd) }
