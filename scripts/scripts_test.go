package scripts

import (
	"strings"
	"testing"
)

// TestCreateTunDevBatTakesDNSFromCaller 固定 Windows 创建脚本的参数契约：
//   - DNS 必须来自调用方传入的第 8 个位置参数（由 cmd/easyss 的 tunDNS 计算），
//     而不是硬编码某个公网解析器。历史上它写死 8.8.8.8，导致 Windows 与
//     darwin/linux 的取值不一致，并且完全忽略 enable_forward_dns。
//   - 可选的 %7/%8 必须用 %~N 去引号：Go 把空参数编码成字面 ""，cmd 会把引号
//     保留在批处理参数里，普通 "%server_ip_v6%" 会看起来非空，让服务端没有
//     IPv6 时误入 ipv6 分支。
func TestCreateTunDevBatTakesDNSFromCaller(t *testing.T) {
	script := string(CreateTunDevBat)

	for _, want := range []string{
		"set tun_dns=%~8",
		"set server_ip_v6=%~7",
		"set dns name=%tun_device% static %tun_dns%",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("create_tun_dev_windows.bat must contain %q", want)
		}
	}

	if strings.Contains(script, "8.8.8.8") {
		t.Error("create_tun_dev_windows.bat must not hardcode a public DNS address; it is passed in by the caller")
	}
}
