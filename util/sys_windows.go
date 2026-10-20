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

// mibIpforwardrow 镜像 MIB_IPFORWARDROW（iphlpapi.h）：固定 14 个 DWORD（56 字节），
// 匿名字段占位保住偏移量，IP 地址以网络字节序存储。
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

// getIpForwardTable 以 MIB_IPFORWARDROW 行返回 IPv4 路由表：x/sys/windows 未封装该 API，
// 表前 4 字节是条目数、后面是定长行，首次传 nil 缓冲区只取所需大小。
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

// routeCandidate 是一条 0.0.0.0/0 默认路由条目。
type routeCandidate struct {
	index   uint32
	nextHop uint32
	metric  uint32
}

// Windows 的路由查找会拒绝 0.0.0.0/8 目标，探测 0.0.0.1 行不通，路由表是唯一途径；
// TUN 激活时 netsh 加的那条 metric 通常最低，必须靠 IsTunIface 跳过才能拿到物理默认接口。
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

// defaultRouteCandidates 返回 0.0.0.0/0 条目，按 metric 升序（最低的在前）。
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

// ipFromUint32 把网络字节序的 uint32（MIB_IPFORWARDROW 的存储形式）转成 net.IP。
func ipFromUint32(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
