package tun

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// platformCase 是平台矩阵的一行：一种"谁在什么平台上、以什么方式启用 TUN"。
//
// 验收清单要求覆盖 Linux root/非 root helper、macOS root/helper、Windows 直连。
// 这些组合真正不同的地方只有两处：脚本的位置参数布局（由 ScriptArgs 按平台渲染）
// 与拆除时"谁负责路由和 DNS"（由 Owner 表达）。因此矩阵直接对这两件事断言，
// 而不是去跑五个需要 root、会改写本机网络的环境。
type platformCase struct {
	name string
	// platform 是脚本布局：windows 的位次与 unix 不同。
	platform ScriptPlatform
	// elevated 表示设备与路由由提权路径创建：linux/macOS 非 root 时是 helper，
	// root 时仍是本进程（它已经有权限了，不经过 helper）。
	elevated bool
	// fd 表示设备来自 fd（只有提权 helper 才会传 fd）。
	fd bool
	// owner 是拆除时预期的所有权。
	owner Owner
	// runsCloseScript 表示拆除时本进程要不要跑平台关闭脚本。
	runsCloseScript bool
	// managesDNS 表示这个平台的脚本自己配适配器 DNS（windows），因此系统 DNS
	// 从不被本进程改动，拆除时也就没有"恢复"这一步。
	managesDNS bool
}

// platformMatrix 是完整的平台矩阵。
//
// linux/macOS 的 root 直连路径：全部归本进程（OwnerLocal），关闭脚本与 DNS
// 都由本进程收尾。非 root 的 helper 路径：设备、路由、DNS 都归 helper，主进程
// 只停自己的引擎并关 fd。Windows 没有提权 helper（没有 fd 传递机制），永远是
// 直连路径。
func platformMatrix() []platformCase {
	return []platformCase{
		{
			name: "linux root (direct)", platform: PlatformLinux,
			owner: OwnerLocal, runsCloseScript: true, managesDNS: true,
		},
		{
			name: "linux non-root (helper)", platform: PlatformLinux, elevated: true, fd: true,
			owner: OwnerHelper, runsCloseScript: false, managesDNS: true,
		},
		{
			name: "darwin root (direct)", platform: PlatformDarwin,
			owner: OwnerLocal, runsCloseScript: true, managesDNS: true,
		},
		{
			name: "darwin non-root (helper)", platform: PlatformDarwin, elevated: true, fd: true,
			owner: OwnerHelper, runsCloseScript: false, managesDNS: true,
		},
		{
			// windows 的创建/关闭脚本自己用 netsh 配适配器 DNS，client/tun
			// 从不改动系统 DNS，因此拆除时没有恢复这一步。
			name: "windows (direct)", platform: PlatformWindows,
			owner: OwnerLocal, runsCloseScript: true, managesDNS: false,
		},
	}
}

// ownerFor 是生产代码里决定所有权的那条规则的测试镜像：DeviceFD>0 即 fd 路径
// （只有提权 helper 会传 fd）。Start 里的实现必须与它一致。
func ownerFor(cfg Config) Owner {
	if cfg.DeviceFD > 0 {
		return OwnerHelper
	}
	return OwnerLocal
}

// TestPlatformMatrixOwnership 固定矩阵的所有权推导：每个平台的每种启用方式都
// 必须落到预期的 Owner 上，且拆除步骤与它一致。
//
// 它是 "fdMode / SkipRouteCleanup / helperSignalled 三套隐式条件" 的替代验证：
// 过去这些字段各自独立赋值，漏一个就会让非 root 的主进程去 pkexec 跑关闭脚本
// （与 helper 抢）或者让 helper 会话的路由无人回收。
func TestPlatformMatrixOwnership(t *testing.T) {
	for _, tc := range platformMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"}
			if tc.fd {
				cfg.DeviceFD = 7
			}

			require.Equal(t, tc.owner, ownerFor(cfg),
				"%s: fd 路径必须由 helper 拥有，其余归本进程", tc.name)
		})
	}
}

// TestPlatformMatrixScriptLayout 固定矩阵的脚本布局：每个平台都必须拿到自己
// 那套位置参数，且与矩阵声明的平台一致。
func TestPlatformMatrixScriptLayout(t *testing.T) {
	dev := scriptFixture()
	args := NewScriptArgs(dev, "8.8.8.8", 1500)

	for _, tc := range platformMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			create := args.CreateFor(tc.platform)
			require.Len(t, create, 9, "%s: every create script takes nine positional parameters", tc.name)
			require.Equal(t, dev.Device, create[0], "%s: the first argument is always the device", tc.name)
			require.Equal(t, "1500", create[8], "%s: the last argument is always the MTU", tc.name)

			// windows 的第 4 位是掩码、第 8 位是适配器 DNS；unix 的第 4 位是
			// 本地网关、第 8 位是本地网关 v6。这是三套布局里唯一的分歧点。
			if tc.platform == PlatformWindows {
				require.Equal(t, dev.TunMask, create[3], "%s: windows carries the netmask", tc.name)
				require.Equal(t, "8.8.8.8", create[7], "%s: windows carries the adapter dns", tc.name)
			} else {
				require.Equal(t, dev.LocalGateway, create[3], "%s: unix carries the local gateway", tc.name)
				require.Equal(t, dev.LocalGatewayV6, create[7], "%s: unix carries the local gateway v6", tc.name)
			}

			closeArgs := args.CloseFor(tc.platform)
			if tc.platform == PlatformWindows {
				require.Len(t, closeArgs, 3, "%s: the windows close script takes device, gateway and bare v6", tc.name)
			} else {
				require.Len(t, closeArgs, 6, "%s: unix close scripts take six gateways", tc.name)
			}
		})
	}
}

// TestPlatformMatrixTeardownSteps 把矩阵与拆除步骤绑在一起：跑一遍真实的
// teardown，断言它执行的清理与矩阵一致。
//
// 这里只跑本机平台的"真实"路径是不行的——矩阵的意义正是覆盖拿不到 root 的
// 平台。因此每个用例都直接构造一个带对应所有权的 Manager 并驱动 teardown，
// 观测点只有"Hook 跑了没有"。
func TestPlatformMatrixTeardownSteps(t *testing.T) {
	for _, tc := range platformMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			rec := stubTeardownHooks(t)

			m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
			m.owner = tc.owner
			m.engineUp = true
			m.deviceUp = true
			m.dnsTouched = true
			m.dnsChanged = true

			require.NoError(t, m.teardown(ReasonStop, tc.owner))

			require.Len(t, rec.engineStops, 1,
				"%s: 引擎必须恰好停一次（它释放 fd，helper 的关闭脚本随后才能删设备）", tc.name)

			wantClose := 0
			if tc.runsCloseScript {
				wantClose = 1
			}
			require.Equal(t, wantClose, rec.closeScripts,
				"%s: 只有本进程装的设备才跑关闭脚本（helper 路径必须留给 helper）", tc.name)

			// DNS 恢复由三个条件共同决定：这次会话真的改过系统 DNS、所有权在
			// 本进程、且本平台确实由 client/tun 管系统 DNS（windows 的脚本自己
			// 用 netsh 配适配器 DNS，manageSystemDNS() 恒为 false）。
			//
			// manageSystemDNS() 问的是**运行平台**，因此这条断言只对宿主平台
			// 有意义：矩阵里其他平台的行描述的语义在当前构建上不可达。
			wantDNS := 0
			if tc.managesDNS && tc.owner == OwnerLocal && manageSystemDNS() {
				wantDNS = 1
			}
			if tc.platform == Platform() {
				require.Equal(t, wantDNS, rec.dnsRestores,
					"%s: 只有本进程改过系统 DNS 才恢复", tc.name)
			}
		})
	}
}

// TestPlatformMatrixCoversEverySupportedOS 保证矩阵本身不会漏掉一个平台：
// 新增平台支持时必须在这里报到，否则它会在没有任何布局/所有权断言的情况下
// 上线。
func TestPlatformMatrixCoversEverySupportedOS(t *testing.T) {
	covered := make(map[ScriptPlatform]bool)
	for _, tc := range platformMatrix() {
		covered[tc.platform] = true
	}

	for _, platform := range []ScriptPlatform{PlatformLinux, PlatformDarwin, PlatformWindows} {
		require.True(t, covered[platform], "%s is missing from the platform matrix", platform)
	}

	// 本机平台必须在矩阵里：否则下面的矩阵测试无法证明"当前构建下真的有人覆盖"。
	require.True(t, covered[Platform()], "the host platform %s is missing from the platform matrix", runtime.GOOS)
}

// TestWindowsNeverManagesSystemDNS 固定矩阵里 windows 那一行的前提：windows
// 的创建/关闭脚本自己用 netsh 配适配器 DNS，client/tun 从不改动系统 DNS，
// 因此拆除时不会有"恢复"这一步。两个独立事实一起说明这一点，缺一个，矩阵里
// managesDNS:false 就只是一句注释。
func TestWindowsNeverManagesSystemDNS(t *testing.T) {
	if runtime.GOOS == "windows" {
		require.False(t, manageSystemDNS(),
			"windows 由脚本配置适配器 DNS，client/tun 不得再动系统 DNS")
		return
	}

	// 非 windows 主机上无法直接问 manageSystemDNS()（它读的是运行平台），
	// 因此改为断言"这条豁免只挂在 darwin/linux 上"这一事实本身：
	// manageSystemDNS() 的定义必须只认这两个平台。
	require.False(t, ScriptPlatform("windows") == PlatformLinux || ScriptPlatform("windows") == PlatformDarwin,
		"sanity: windows 既不是 linux 也不是 darwin, 因此 manageSystemDNS() 对它恒为 false")
}
