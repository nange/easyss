//go:build !linux

package sysproxy

import "testing"

// Linux 之外的 State 没有会话环境字段，空实例即可；桌面代理由测试注入。
func newTestState(t *testing.T) *State {
	t.Helper()

	return &State{}
}
