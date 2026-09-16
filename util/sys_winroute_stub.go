//go:build !windows

package util

import "net"

// defaultRouteFromWinTable 在 windows 上实现；其他平台回退到
// SysGatewayAndDevice 中的 netroute 探测。
func defaultRouteFromWinTable() (*net.Interface, net.IP, error) {
	return nil, nil, errUnsupportedPlatform
}
