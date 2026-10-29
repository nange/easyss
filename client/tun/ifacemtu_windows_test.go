//go:build windows

package tun

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TestInterfaceMTUMatchesTheIPv4Entry 守住 Windows 的取值来源：net.Interface.MTU 跟的是
// IPv6 接口的 NlMtu（wintun 适配器上是驱动默认的 65535），而创建脚本设置的是 IPv4 的
// NlMtu。装过 wintun 适配器（WireGuard/Tailscale/easyss 自身）的机器上两者必然不同，
// 退回 net.Interface.MTU 会在这里失败；CI 上则只验证名称到 IP 接口条目的映射。
func TestInterfaceMTUMatchesTheIPv4Entry(t *testing.T) {
	t.Parallel()

	ifaces, err := net.Interfaces()
	require.NoError(t, err)

	checked := 0
	for _, iface := range ifaces {
		row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: uint32(iface.Index)}
		if err := windows.GetIpInterfaceEntry(&row); err != nil || row.NlMtu == 0 {
			continue // 没有 IPv4 条目的适配器（例如仅绑定了 IPv6）不在探针范围内
		}

		mtu, err := interfaceMTU(iface.Name)
		require.NoError(t, err)
		require.Equal(t, int(row.NlMtu), mtu, iface.Name)
		checked++
	}
	require.NotZero(t, checked, "loopback always has an ipv4 entry")
}
