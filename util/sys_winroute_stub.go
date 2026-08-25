//go:build !windows

package util

import "net"

// defaultRouteFromWinTable is implemented on windows; other platforms fall
// back to the netroute probe in SysGatewayAndDevice.
func defaultRouteFromWinTable() (*net.Interface, net.IP, error) {
	return nil, nil, errUnsupportedPlatform
}
