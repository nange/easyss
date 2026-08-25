//go:build windows

package util

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errNoDefaultRoute = errors.New("no default route found")

// mibIpforwardrow mirrors MIB_IPFORWARDROW (iphlpapi.h). The layout is fixed
// and documented (14 DWORDs = 56 bytes); only the fields needed for the
// default-route lookup are named.
type mibIpforwardrow struct {
	dest    uint32
	mask    uint32
	policy  uint32
	nextHop uint32
	ifIndex uint32
	typ     uint32
	proto   uint32
	age     uint32
	nextAS  uint32
	metric1 uint32
	metric2 uint32
	metric3 uint32
	metric4 uint32
	metric5 uint32
}

var procGetIpForwardTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIpForwardTable")

// routeCandidate is one 0.0.0.0/0 default-route entry.
type routeCandidate struct {
	index   uint32
	nextHop uint32
	metric  uint32
}

// defaultRouteFromWinTable returns the physical interface and gateway of the
// IPv4 default route via GetIpForwardTable. Windows may hold several 0.0.0.0/0
// entries (e.g. the easyss TUN device's own default route, added by netsh
// when the static gateway is configured); the easyss TUN interface is skipped
// so the physical default interface is returned while TUN is active.
func defaultRouteFromWinTable() (*net.Interface, net.IP, error) {
	var size uint32
	r, _, _ := procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 && r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, nil, fmt.Errorf("GetIpForwardTable: %w", windows.Errno(r))
	}

	buf := make([]byte, size)
	r, _, _ = procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		return nil, nil, fmt.Errorf("GetIpForwardTable: %w", windows.Errno(r))
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	rows := unsafe.Slice((*mibIpforwardrow)(unsafe.Pointer(&buf[4])), int(num))

	for _, c := range defaultRouteCandidates(rows) {
		iface, err := net.InterfaceByIndex(int(c.index))
		if err != nil {
			continue
		}
		if IsTunIface(iface) {
			continue
		}
		return iface, ipFromUint32(c.nextHop), nil
	}
	return nil, nil, errNoDefaultRoute
}

// defaultRouteCandidates returns the 0.0.0.0/0 default-route entries sorted
// by metric (lowest first).
func defaultRouteCandidates(rows []mibIpforwardrow) []routeCandidate {
	var cands []routeCandidate
	for _, row := range rows {
		if row.dest != 0 || row.mask != 0 {
			continue
		}
		cands = append(cands, routeCandidate{index: row.ifIndex, nextHop: row.nextHop, metric: row.metric1})
	}
	for i := 1; i < len(cands); i++ {
		for j := i; j > 0 && cands[j].metric < cands[j-1].metric; j-- {
			cands[j], cands[j-1] = cands[j-1], cands[j]
		}
	}
	return cands
}

// ipFromUint32 converts a network-byte-order IPv4 address (as stored in
// MIB_IPFORWARDROW) to a net.IP.
func ipFromUint32(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
