//go:build !darwin && !linux

package main

// 其他平台没有提权 helper 与路由残留探测（拆除见 tray_tun_teardown_other.go）。
type tunOps struct{}
