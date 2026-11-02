package config

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// 在线猜测的成本全由攻击者承担：服务端每次猜测只付 HKDF + 一次 AEAD 解封（约 4µs），
// PBKDF2 只在客户端/启动时算一次，所以口令长度是唯一长期有效的防线。8 字符
// （36^8≈2.8e12）是硬下限，16 字符给人工口令的非均匀分布留余量。
const (
	MinPasswordLen  = 8
	WarnPasswordLen = 16
)

var ErrPasswordTooShort = errors.New("password is too short")

// CheckPassword 只校验"有口令时"的长度下限。空口令不在这里拒绝：DeriveMasterKey 会返回
// ErrPasswordEmpty，启动同样失败，且调用方按那个错误做本地化提示。
func CheckPassword(password string) error {
	if n := utf8.RuneCountInString(password); n > 0 && n < MinPasswordLen {
		return fmt.Errorf("%w: %d characters, want at least %d", ErrPasswordTooShort, n, MinPasswordLen)
	}
	return nil
}

// PasswordWeak 报告口令是否低于建议长度（8-15 字符）：调用方在启动时告警，不阻止启动。
func PasswordWeak(password string) bool {
	n := utf8.RuneCountInString(password)
	return n > 0 && n < WarnPasswordLen
}
