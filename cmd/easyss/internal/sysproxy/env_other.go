//go:build !linux

package sysproxy

// State 在 Linux 之外不管理会话环境（set/unset 是空操作）；系统级代理由 desktop
// 字段读写，Windows/macOS 的浏览器确实遵守 wzshiming/sysproxy 写入的设置。
type State struct {
	desktop desktopProxy
}

func (*State) set(string) (bool, error) { return false, nil }

func (*State) unset() (bool, error) { return false, nil }
