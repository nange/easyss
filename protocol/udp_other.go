//go:build !windows

package protocol

// IsUDPMessageTooLong 在 Unix 上恒为 false：UDP 读取超长数据报时会静默截断
// （n == len(readBuf)），不会返回错误。只有 Windows 会返回 WSAEMSGSIZE。
func IsUDPMessageTooLong(_ error) bool { return false }
