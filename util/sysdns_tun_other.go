//go:build !linux

package util

import "slices"

// SetSysDNSForTun 为 TUN 模式配置 DNS 解析。除 Linux 外的平台在网络服务或
// 连接层面维护自己的 DNS 配置（macOS 用 networksetup，Windows 用注册表），
// 并通过路由表解析，因此 TUN 路由会把查询带入隧道，而无需任何按链路
// （per-link）的解析器状态：
// 普通的系统 DNS 就已足够。
func SetSysDNSForTun(_ string, v []string) error {
	return SetSysDNS(v)
}

// EnsureSysDNSForTun 在这些平台上无需重新断言任何配置。
func EnsureSysDNSForTun(_ string, _ []string) error {
	return nil
}

// RestoreSysDNSForTun 恢复 TUN 启动前保存的 DNS 服务器。
func RestoreSysDNSForTun(_ string, origin []string) error {
	if len(origin) == 0 {
		return SetSysDNS([]string{"empty"})
	}

	curr, err := SysDNS()
	if err != nil {
		return err
	}
	if slices.Equal(curr, origin) {
		return nil
	}
	return SetSysDNS(origin)
}
