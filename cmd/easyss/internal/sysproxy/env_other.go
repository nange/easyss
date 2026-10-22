//go:build !linux

package sysproxy

// State 在 Linux 之外是空操作：macOS 和 Windows 有真正的系统级代理配置，
// wzshiming/sysproxy 包已经会更新它，而且那里的浏览器确实会遵守它。
type State struct{}

func (*State) set(string) (bool, error) { return false, nil }

func (*State) unset() (bool, error) { return false, nil }
