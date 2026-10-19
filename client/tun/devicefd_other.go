//go:build !darwin && !linux

package tun

// 非 darwin/linux 平台没有提权 helper 传回 fd 的机制（Config.DeviceFD 恒为 0），
// 这两个定义只是让 Manager 的跨平台代码保持同一形状。

func closeRawDeviceFD(int) error { return ErrNotFDPath }
