package tunhelper

import "strings"

// Windows 创建脚本安装的 8 条分流默认路由；close_tun_dev_windows.bat 按同一组目标删除，
// 两侧必须保持同步，否则停止 TUN 后残留的路由会把全机 IPv4 流量送进无人读取的设备。
func isWindowsSplitRoute(dst string) bool {
	switch dst {
	case "1.0.0.0", "2.0.0.0", "4.0.0.0", "8.0.0.0",
		"16.0.0.0", "32.0.0.0", "64.0.0.0", "128.0.0.0":
		return true
	default:
		return false
	}
}

// parseRoutePrintResidue 检查 `route print -4` 里是否还有指向 TUN 网关的分流路由。
// 列序与系统语言无关：第 1、2、3 列分别是目的地址、掩码、网关（与关闭脚本的 for /f
// "tokens=1,2,3" 一致）。
func parseRoutePrintResidue(out, tunGW string) (string, bool) {
	if tunGW == "" {
		return "", false
	}

	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != tunGW || !isWindowsSplitRoute(fields[0]) {
			continue
		}
		return strings.TrimSpace(line), true
	}
	return "", false
}
