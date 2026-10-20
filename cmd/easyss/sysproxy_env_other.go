//go:build !linux

package main

// proxyEnvState 在 Linux 之外是空操作：macOS 和 Windows 有真正的系统级代理配置，
// sysproxy 包已经会更新它，而且那里的浏览器确实会遵守它。
type proxyEnvState struct{}

func newProxyEnvState() *proxyEnvState { return &proxyEnvState{} }

func (*proxyEnvState) set(string) (bool, error) { return false, nil }

func (*proxyEnvState) unset() (bool, error) { return false, nil }
