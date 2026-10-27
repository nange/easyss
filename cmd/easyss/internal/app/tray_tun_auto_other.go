//go:build !darwin && !linux && !windows && !headless

package app

// tunUpAuto 在这些平台没有提权 helper 路径，直接创建设备。
func (s *session) tunUpAuto() error { return s.tunUp() }
