//go:build windows

package util

import "fmt"

// SetSysDNS 在此平台上为空操作。
func SetSysDNS(v []string) error {
	return nil
}

// SysDNS 返回系统的 DNS 服务器，解析自 `ipconfig /all` 的输出。
func SysDNS() ([]string, error) {
	out, err := Command("ipconfig", "/all")
	if err != nil {
		return nil, err
	}
	return parseDNSServersFromIPConfig(out), nil
}

// SysDNSViaOSAScript 在非 darwin 平台上不受支持，调用会返回错误。
func SysDNSViaOSAScript() ([]string, error) {
	return nil, fmt.Errorf("SysDNSViaOSAScript is only supported on macOS")
}

// SetSysDNSViaOSAScript 在非 darwin 平台上不受支持，调用会返回错误。
func SetSysDNSViaOSAScript(servers []string) error {
	return fmt.Errorf("SetSysDNSViaOSAScript is only supported on macOS")
}
