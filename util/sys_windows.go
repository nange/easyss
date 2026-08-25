//go:build windows

package util

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errNoDefaultRoute = errors.New("no default route found")

// mibIpforwardrow mirrors MIB_IPFORWARDROW (iphlpapi.h): a fixed layout of
// 14 DWORDs (56 bytes). Only the fields used by the default-route lookup are
// named; the anonymous placeholders keep the offsets of the named fields
// correct. IP addresses are stored in network byte order.
type mibIpforwardrow struct {
	dest    uint32    // dwForwardDest
	mask    uint32    // dwForwardMask
	_       uint32    // dwForwardPolicy
	nextHop uint32    // dwForwardNextHop
	ifIndex uint32    // dwForwardIfIndex
	_       [4]uint32 // dwForwardType, dwForwardProto, dwForwardAge, dwForwardNextHopAS
	metric1 uint32    // dwForwardMetric1
	_       [4]uint32 // dwForwardMetric2..dwForwardMetric5
}

var procGetIpForwardTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIpForwardTable")

// getIpForwardTable returns the IPv4 routing table as MIB_IPFORWARDROW rows.
// The table starts with a 4-byte entry count followed by the fixed-size
// rows; x/sys/windows does not wrap this API, so the buffer is laid out with
// unsafe. GetIpForwardTable is called twice: the first call (nil buffer)
// reports the required size, the second call fills it.
func getIpForwardTable() ([]mibIpforwardrow, error) {
	var size uint32
	r, _, _ := procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 && r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("GetIpForwardTable: %w", windows.Errno(r))
	}

	buf := make([]byte, size)
	r, _, _ = procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		return nil, fmt.Errorf("GetIpForwardTable: %w", windows.Errno(r))
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	return unsafe.Slice((*mibIpforwardrow)(unsafe.Pointer(&buf[4])), int(num)), nil
}

// routeCandidate is one 0.0.0.0/0 default-route entry.
type routeCandidate struct {
	index   uint32
	nextHop uint32
	metric  uint32
}

// defaultRouteFromWinTable returns the physical interface and gateway of the
// IPv4 default route. Windows must be handled differently from darwin/linux:
// its route lookup rejects 0.0.0.0/8 destinations, so the physical interface
// cannot be found by probing 0.0.0.1 — the routing table is the only way.
// While TUN is active the table holds several 0.0.0.0/0 entries: netsh adds
// a default route to the easyss TUN device itself (usually with the lowest
// metric), which is skipped so the physical default interface is returned.
func defaultRouteFromWinTable() (*net.Interface, net.IP, error) {
	rows, err := getIpForwardTable()
	if err != nil {
		return nil, nil, err
	}

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
	slices.SortFunc(cands, func(a, b routeCandidate) int {
		return cmp.Compare(a.metric, b.metric)
	})
	return cands
}

// ipFromUint32 converts a network-byte-order IPv4 address (as stored in
// MIB_IPFORWARDROW) to a net.IP.
func ipFromUint32(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
