//go:build !linux

package util

import "slices"

// 除 Linux 外的平台按网络服务/连接维护 DNS 并经由路由表解析，因此 TUN 路由会把
// 查询带入隧道，不需要任何按链路（per-link）的解析器状态。
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
