//go:build windows

package protocol

import (
	"errors"

	"golang.org/x/sys/windows"
)

// 报告 err 是否为"数据报大于接收缓冲"的平台错误。Windows 的 WSARecvfrom 返回
// WSAEMSGSIZE 而非像 Unix 那样静默截断；调用方应丢弃该数据报，而不是当成会话错误。
func IsUDPMessageTooLong(err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE)
}
