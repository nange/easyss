//go:build windows

package protocol

import (
	"errors"

	"golang.org/x/sys/windows"
)

// IsUDPMessageTooLong 报告 err 是否是"数据报大于接收缓冲"的平台错误。
//
// Windows 的 WSARecvfrom 在缓冲装不下数据报时返回 WSAEMSGSIZE，而不是像
// Unix 那样静默截断；调用方应把它当作"丢弃这一条数据报"而不是会话错误。
// Unix 侧由 n == len(readBuf) 判断截断，见 udp_other.go 的桩。
func IsUDPMessageTooLong(err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE)
}
