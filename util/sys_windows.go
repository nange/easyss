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

// mibIpforwardrow 镜像 MIB_IPFORWARDROW（iphlpapi.h）：固定布局，
// 共 14 个 DWORD（56 字节）。只为默认路由查找用到的字段命名；
// 匿名字段占位符用于保证已命名字段的偏移量正确。IP 地址以网络字节序存储。
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

// getIpForwardTable 以 MIB_IPFORWARDROW 行的形式返回 IPv4 路由表。
// 表以 4 字节的条目计数开头，后面跟着定长的行；
// x/sys/windows 没有封装该 API，因此缓冲区用 unsafe 布局。
// GetIpForwardTable 会被调用两次：第一次调用（nil 缓冲区）
// 返回所需大小，第二次调用填充缓冲区。
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

// defaultRouteFromWinTable 返回 IPv4 默认路由的物理接口和网关。
// Windows 必须与 darwin/linux 区别处理：其路由查找会拒绝 0.0.0.0/8
// 目标，因此无法通过探测 0.0.0.1 找到物理接口 — 路由表是唯一途径。
// TUN 激活时表中会持有多个 0.0.0.0/0 条目：netsh 会向 easyss TUN
// 设备本身添加一条默认路由（通常 metric 最低），该条目会被跳过，
// 从而返回物理默认接口。
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

// defaultRouteCandidates 返回 0.0.0.0/0 默认路由条目，按 metric 排序
// （最低的在前）。
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

// ipFromUint32 将网络字节序的 IPv4 地址（即 MIB_IPFORWARDROW 中的
// 存储形式）转换为 net.IP。
func ipFromUint32(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
