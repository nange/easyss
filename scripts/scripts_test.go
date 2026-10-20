package scripts

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// invalidTildeModifier 匹配 cmd.exe 不接受的批处理参数修饰符（%~ 后不是数字）：
// 它出现在脚本任何位置（含 rem 注释）都会让 cmd.exe 终止整个脚本，一行都不执行。
var invalidTildeModifier = regexp.MustCompile(`%~[^0-9]`)

// TestCreateTunDevBatTakesDNSFromCaller 守住 Windows 创建脚本只从第 8 个位置参数取 DNS，
// 且可选参数必须用 %~7/%~8 去引号：Go 编码的空参数 "" 在 cmd 里看着非空，会误入 ipv6 分支。
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

// TestCreateTunDevBatTakesMTUFromCaller 固定 Windows 创建脚本的 MTU 参数契约：
// wintun 适配器的 MTU 只能由脚本用 netsh 写入（wireguard-go 只把它记在内存里，
// 见 tun_windows.go 的 forcedMTU）。两侧不一致时 netstack 静默丢弃超限包。
func TestCreateTunDevBatTakesMTUFromCaller(t *testing.T) {
	script := string(CreateTunDevBat)

	for _, want := range []string{
		"set tun_mtu=%~9",
		`netsh interface ipv4 set subinterface "%tun_device%" mtu=%tun_mtu%`,
		`netsh interface ipv6 set subinterface "%tun_device%" mtu=%tun_mtu%`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("create_tun_dev_windows.bat must contain %q", want)
		}
	}

	// MTU 是会话级接口设置，写进注册表会在换回默认值后留下持久残留。
	if strings.Contains(script, "store=persistent") {
		t.Error("create_tun_dev_windows.bat must apply the MTU with store=active, not persistently")
	}
}

// TestTunDevBatTildeModifiersAreValid 用文本级检查兜住非法修饰符——它会让
// cmd.exe 拒绝整个脚本，而 Windows 脚本测试只在 Windows CI 上跑。
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

// TestCloseTunDevBatHasItsOwnExitCode 守住关闭脚本的退出码：引擎先停、脚本后跑，适配器通常
// 已注销，cmd.exe 会沿用最后一条 netsh 的退出码而误报失败，故设备守卫判退出码而非输出文本。
func TestCloseTunDevBatHasItsOwnExitCode(t *testing.T) {
	script := string(CloseTunDevBat)

	for _, want := range []string{
		`call netsh interface show interface name="%tun_device%" >nul 2>&1`,
		"if errorlevel 1 if not errorlevel 2 exit /b 0",
		`for /f "tokens=1,2,3" %%a in ('route print -4') do (`,
		`if "%%c"=="%tun_gw%" for %%p in (1.0.0.0 2.0.0.0 4.0.0.0 8.0.0.0 16.0.0.0 32.0.0.0 64.0.0.0 128.0.0.0) do (`,
		"residual split routes via %tun_gw%",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("close_tun_dev_windows.bat must contain %q", want)
		}
	}

	// 末尾必须显式成功退出：否则 cmd.exe 会沿用最后一条 netsh 的退出码（对象不存在时也是 1）。
	if !strings.HasSuffix(strings.TrimSpace(script), "exit /b 0") {
		t.Error(`close_tun_dev_windows.bat must end with an explicit "exit /b 0"`)
	}
}

// TestTunDevBatsStayCrlfAndBomFree 守住 .bat 的 CRLF 与无 BOM：cmd.exe 按 OEM 代码页逐行读，
// 中文 Windows 上 LF 会让多字节注释错位、注释被当成命令执行（运行期另有 normalizeScriptEOL 兜底）。
func TestTunDevBatsStayCrlfAndBomFree(t *testing.T) {
	for name, content := range map[string][]byte{
		"create_tun_dev_windows.bat": CreateTunDevBat,
		"close_tun_dev_windows.bat":  CloseTunDevBat,
	} {
		if bytes.HasPrefix(content, []byte{0xEF, 0xBB, 0xBF}) {
			t.Errorf("%s must not carry a UTF-8 BOM", name)
		}
		if !utf8.Valid(content) {
			t.Errorf("%s must stay valid UTF-8", name)
		}

		lf := bytes.Count(content, []byte("\n"))
		crlf := bytes.Count(content, []byte("\r\n"))
		if lf != crlf {
			t.Errorf("%s must use CRLF line endings (%d LF, %d CRLF): .gitattributes declares eol=crlf for *.bat; normalizeScriptEOL in client/tun covers LF at runtime",
				name, lf, crlf)
		}
	}
}

// TestCreateScriptsApplyMTU 守住 linux/darwin 创建脚本必须应用第 9 个位置参数（MTU）：
// fd 路径下 tun2socks 只能改自己 netstack 的 MTU，两侧不一致会静默丢弃超限包。
func TestCreateScriptsApplyMTU(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		want   string
	}{
		{
			name:   "linux",
			script: string(CreateTunDevSh),
			want:   `run_idem mtu ip link set dev "$tun_device" mtu "$tun_mtu"`,
		},
		{
			name:   "darwin",
			script: string(CreateTunDevDarwinSh),
			want:   `fail mtu ifconfig "$tun_device" mtu "$tun_mtu"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 必须 ${9:-}：darwin 脚本带 set -u，$9 在只给 8 个实参时以 "unbound variable" 中止。
			if !strings.Contains(tc.script, "tun_mtu=${9:-}") {
				t.Errorf("%s must take the MTU as its optional 9th positional parameter", tc.name)
			}
			if !strings.Contains(tc.script, tc.want) {
				t.Errorf("%s must apply the MTU with %q", tc.name, tc.want)
			}
			// 空 MTU 必须跳过：保留设备默认值不是失败，与 Windows 脚本对第 9 个参数一致。
			if !strings.Contains(tc.script, `if [ -n "$tun_mtu" ]; then`) {
				t.Errorf("%s must skip the MTU when the caller did not pass one", tc.name)
			}
		})
	}
}
