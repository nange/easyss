//go:build !windows

package tun

import "net"

// darwin/linux 的 net.Interface.MTU 就是创建脚本写到那条链路上的 MTU。
func interfaceMTU(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.MTU, nil
}
