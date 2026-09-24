package scripts

import (
	"regexp"
	"strings"
	"testing"
)

// invalidTildeModifier 匹配 cmd.exe 不接受的批处理参数路径修饰符（%~ 后面不是
// 数字）。它出现在脚本的任何位置——包括 rem 注释里——都会让 cmd 用
// "The following usage of the path operator in batch-parameter substitution is
// invalid" 终止整个脚本，脚本里一行都不会执行。
var invalidTildeModifier = regexp.MustCompile(`%~[^0-9]`)

// TestCreateTunDevBatTakesDNSFromCaller 固定 Windows 创建脚本的参数契约：
//   - DNS 必须来自调用方传入的第 8 个位置参数（由 cmd/easyss 的 tunDNS 计算），
//     而不是硬编码某个公网解析器。历史上它写死 8.8.8.8，导致 Windows 与
//     darwin/linux 的取值不一致；该取值与本会话实测可达的解析器绑定，和
//     enable_forward_dns（只服务 LAN 客户）无关。
//   - 可选的 %7/%8 必须去引号：Go 把空参数编码成字面 ""，cmd 会把引号保留在
//     批处理参数里，普通 "%server_ip_v6%" 会看起来非空，让服务端没有 IPv6 时
//     误入 ipv6 分支。
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

// TestTunDevBatTildeModifiersAreValid 防止把非法的参数修饰符写进批处理脚本。
// 这类错误在任何位置都会让 cmd.exe 拒绝整个脚本（见 invalidTildeModifier），
// 而 Windows 的脚本测试只在 Windows CI 上运行，所以这里用文本级检查兜住它。
func TestTunDevBatTildeModifiersAreValid(t *testing.T) {
	for name, content := range map[string]string{
		"create_tun_dev_windows.bat": string(CreateTunDevBat),
		"close_tun_dev_windows.bat":  string(CloseTunDevBat),
	} {
		loc := invalidTildeModifier.FindStringIndex(content)
		if loc == nil {
			continue
		}
		end := min(loc[0]+40, len(content))
		t.Errorf("%s: %q is not a valid batch-parameter modifier: cmd.exe aborts the whole script",
			name, content[loc[0]:end])
	}
}
