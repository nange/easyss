package tun

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// platformCase 是平台矩阵的一行。这些组合真正不同的只有两处：脚本的位置参数布局
// （ScriptArgs 按平台渲染）与拆除时"谁负责路由和 DNS"（Owner）。矩阵直接对这两件事断言，
// 不去跑需要 root、会改写本机网络的真实环境。
type platformCase struct {
	name     string
	platform ScriptPlatform
	// elevated：非 root 时由 helper 创建，root 时仍是本进程（已有权限，不经过 helper）。
	elevated        bool
	fd              bool
	owner           Owner
	runsCloseScript bool
	// managesDNS 表示这个平台由 client/tun 管理系统 DNS；windows 由脚本用 netsh 配适配器 DNS。
	managesDNS bool
}

// platformMatrix 是完整的平台矩阵：root 直连路径全部归本进程（OwnerLocal），
// 非 root 的 helper 路径设备/路由/DNS 都归 helper，Windows 没有 fd 传递机制，永远是直连路径。
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
			// windows 脚本自己用 netsh 配适配器 DNS，client/tun 从不改动系统 DNS。
			name: "windows (direct)", platform: PlatformWindows,
			owner: OwnerLocal, runsCloseScript: true, managesDNS: false,
		},
	}
}

// TestPlatformMatrixOwnership 固定所有权推导：每种启用方式都必须落到预期的 Owner 上。
// 直接调用生产代码的推导点 ownerForConfig，不从测试里抄规则——抄一份只能证明两份规则此刻相同。
// 推错会让非 root 的主进程去 pkexec 跑关闭脚本与 helper 抢，或让 helper 会话的路由无人回收。
func TestPlatformMatrixOwnership(t *testing.T) {
	for _, tc := range platformMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"}
			if tc.fd {
				cfg.DeviceFD = 7
			}

			require.Equal(t, tc.owner, ownerForConfig(cfg),
				"%s: fd 路径必须由 helper 拥有，其余归本进程", tc.name)
		})
	}
}

func TestPlatformMatrixScriptLayout(t *testing.T) {
	dev := scriptFixture()
	args := NewScriptArgs(dev, "8.8.8.8", 1500)

	for _, tc := range platformMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			create := args.CreateFor(tc.platform)
			require.Len(t, create, 9, "%s: every create script takes nine positional parameters", tc.name)
			require.Equal(t, dev.Device, create[0], "%s: the first argument is always the device", tc.name)
			require.Equal(t, "1500", create[8], "%s: the last argument is always the MTU", tc.name)

			// 唯一的分歧点：windows 的第 4 位是掩码、第 8 位是适配器 DNS；unix 分别是本地网关与其 v6。
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

// TestPlatformMatrixTeardownSteps 把矩阵与拆除步骤绑在一起：直接构造带对应所有权的 Manager
// 驱动真实 teardown，观测点只有 Hook 跑没跑——矩阵的意义正是覆盖本机拿不到 root 的平台。
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

			// DNS 恢复要三个条件同时成立：会话真的改过系统 DNS、所有权在本进程、平台由 client/tun 管 DNS。
			// teardown 问的是运行平台，因此这条断言只对宿主平台的行有意义。
			wantDNS := 0
			if tc.managesDNS && tc.owner == OwnerLocal && managesSystemDNSFor(Platform()) {
				wantDNS = 1
			}
			if tc.platform == Platform() {
				require.Equal(t, wantDNS, rec.dnsRestores,
					"%s: 只有本进程改过系统 DNS 才恢复", tc.name)
			}
		})
	}
}

// TestPlatformMatrixCoversEverySupportedOS 保证矩阵不漏平台：新增支持时必须在这里报到，
// 否则它会在没有任何布局/所有权断言的情况下上线。
func TestPlatformMatrixCoversEverySupportedOS(t *testing.T) {
	covered := make(map[ScriptPlatform]bool)
	for _, tc := range platformMatrix() {
		covered[tc.platform] = true
	}

	for _, platform := range []ScriptPlatform{PlatformLinux, PlatformDarwin, PlatformWindows} {
		require.True(t, covered[platform], "%s is missing from the platform matrix", platform)
	}

	require.True(t, covered[Platform()], "the host platform %s is missing from the platform matrix", runtime.GOOS)
}

// TestWindowsNeverManagesSystemDNS 固定 windows 那行的前提：脚本自己用 netsh 配适配器 DNS，
// client/tun 从不改动系统 DNS。判据接受显式平台，这条断言在任意宿主机上都真正执行。
func TestWindowsNeverManagesSystemDNS(t *testing.T) {
	require.False(t, managesSystemDNSFor(PlatformWindows),
		"windows 由脚本配置适配器 DNS，client/tun 不得再动系统 DNS")
	require.True(t, managesSystemDNSFor(PlatformLinux), "linux 由 client/tun 管理系统 DNS")
	require.True(t, managesSystemDNSFor(PlatformDarwin), "darwin 由 client/tun 管理系统 DNS")
	require.Equal(t, managesSystemDNSFor(Platform()), manageSystemDNS(),
		"manageSystemDNS 必须只是本机平台的那条判据，不能有第二份规则")
}
