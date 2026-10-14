package scripts

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
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

// TestCreateTunDevBatTakesMTUFromCaller 固定 Windows 创建脚本的 MTU 参数契约。
//
// tun2socks 设不了 wintun 适配器的 MTU：wireguard-go 只把它记在内存里
// （见 tun_windows.go 的 forcedMTU），因此设备的 MTU 只能由调用方传入、由脚本
// 用 netsh 写进接口。两处不一致时 tun2socks 的 netstack 会静默丢弃设备交上来的
// 超限包（UDP、ICMP 与 IP 分片），所以这个参数不能退回硬编码。
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

	// MTU 是会话级的接口设置，不该写进注册表：配置只在本会话生效，
	// 换回默认值时也不会留下持久的残留。
	if strings.Contains(script, "store=persistent") {
		t.Error("create_tun_dev_windows.bat must apply the MTU with store=active, not persistently")
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

// TestCloseTunDevBatHasItsOwnExitCode 固定 Windows 关闭脚本的退出码契约。
//
// "引擎先停、关闭脚本后跑"是三个平台共同的顺序（见 client/tun/tun.go 的 Stop），
// 因此脚本运行时 wintun 适配器通常已经被注销：挂在该接口上的分流路由、v6 地址
// 随接口一起被 Windows 收走，十一条删除全部扑空。缺了下面两样东西时，这会被
// 报成一次清理失败——cmd.exe 会把最后一条 netsh 命令的退出码当成脚本的：
//   - 设备存在性守卫：判据必须是 netsh 的退出码而不是它的输出。接口未注册时
//     netsh 打印的是 "The filename, directory name, or volume label syntax is
//     incorrect."，与真正的失败无法从文本上区分，而且随系统语言变化。
//   - 残留探测：退出码要回答"路由表里还有没有走 TUN 网关的表项"，而不是"某条
//     netsh 命令是否报错"（v6 地址与路由只在服务端有 ipv6 时才安装，纯 ipv4
//     会话的删除必然报错）。
//
// Windows 的脚本行为测试只在 Windows 上运行（见 cmd/easyss 的
// tun_script_windows_test.go），所以这里用文本级检查兜住它。
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

	// 文件末尾必须是一条显式的成功退出：否则 cmd.exe 会把最后一条 netsh 命令的
	// 退出码当成脚本的（对象已不存在时它同样是 1）。
	if !strings.HasSuffix(strings.TrimSpace(script), "exit /b 0") {
		t.Error(`close_tun_dev_windows.bat must end with an explicit "exit /b 0"`)
	}
}

// TestTunDevBatsStayCrlfAndBomFree 固定两个批处理脚本的行尾与编码约定。
//
// cmd.exe 按 OEM 代码页逐行读取批处理文件。在中文 Windows（OEM 代码页 936）上实测：
// LF 行尾会让多字节注释的字节与换行错位，注释文字被当成命令执行、真正的命令行被截断
// （create 脚本一条配置命令都发不出去），而纯 ASCII 注释的 LF 文件不受影响。
//
// 运行期已由 client/tun 的 normalizeScriptEOL 兜住（落盘前统一成 CRLF），所以这条断言
// 守的是仓库约定：.gitattributes 写明 "*.bat text eol=crlf"，检出、diff 与编辑器看到的
// 都该是 CRLF，别让它被悄悄违反。
//
// BOM 一并拒绝：cmd.exe 不把它当空白，它只是第一行多出来的字节。
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

// TestCreateScriptsApplyMTU 固定 linux/darwin 创建脚本的 MTU 契约：设备 MTU 由
// 脚本应用（第 9 个位置参数），与 Windows 脚本用 netsh 做的完全是同一件事。
//
// 它必须落在脚本里而不是 Go 代码里：fd 路径下设备是提权 helper 建的，tun2socks
// 拿到 fd 后只能设置自己 netstack 的 MTU，改不了设备的 MTU；两侧不一致时 netstack
// 会静默丢弃设备交上来的超限包（UDP、ICMP 与 IP 分片）。放在脚本里还能被
// keep-alive 的重放自动修回（休眠/唤醒后 ensureTunRoutes 会重跑创建脚本）。
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
			// ${9:-} 而不是 $9：darwin 脚本带 set -u，直接写 $9 会在调用方
			// 只给 8 个实参时以 "unbound variable" 中止，连地址和路由都配不上。
			if !strings.Contains(tc.script, "tun_mtu=${9:-}") {
				t.Errorf("%s must take the MTU as its optional 9th positional parameter", tc.name)
			}
			if !strings.Contains(tc.script, tc.want) {
				t.Errorf("%s must apply the MTU with %q", tc.name, tc.want)
			}
			// 空值（调用方没传 MTU）必须跳过：保留设备默认值不是失败，
			// 与 Windows 创建脚本对第 9 个参数的处理一致。
			if !strings.Contains(tc.script, `if [ -n "$tun_mtu" ]; then`) {
				t.Errorf("%s must skip the MTU when the caller did not pass one", tc.name)
			}
		})
	}
}
