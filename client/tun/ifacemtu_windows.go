//go:build windows

package tun

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

// Windows 的 net.Interface.MTU 取自 IP_ADAPTER_ADDRESSES.Mtu，跟的是 IPv6 接口的 NlMtu：
// wintun 适配器的 IPv6 MTU 保持驱动默认的 65535，而创建脚本只无条件设置 IPv4 的 NlMtu。
// 探针读 IPv4 的 NlMtu——它才是 Windows 切分本机发往 TUN 的报文所用的值。
func interfaceMTU(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}

	// 单条查询而非 GetIpInterfaceTable：x/sys 的 MibIpInterfaceRow 比 C 结构大 8 字节
	// （TransmitOffload/ReceiveOffload 在 C 里是 1 字节位域），按表遍历会错位。
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: uint32(iface.Index)}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return 0, err
	}
	if row.NlMtu == 0 {
		return 0, fmt.Errorf("tun: interface %s has no ipv4 mtu", name)
	}
	return int(row.NlMtu), nil
}
