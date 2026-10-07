package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"tailscale.com/envknob"

	"github.com/nange/easyss/v3/client/config"
	sharedconfig "github.com/nange/easyss/v3/config"
	vpn "github.com/nange/easyss/v3/vpn"
	vpnnode "github.com/nange/easyss/v3/vpn/node"
)

func vpnTestPaths(t *testing.T) vpnPaths {
	t.Helper()
	dir := t.TempDir()
	return vpnPaths{
		nodeIdentity: dir + "/node-identity.json",
		clientKey:    dir + "/client.key",
		peerAddr:     dir + "/peer.txt",
	}
}

// vpnTestDERPAddr 是测试配置里本节点通告、且所有对端也必须通告的 DERP 地址
// （DERP 私有化要求单一 S，见 vpnnode.assertPeersShareDERP）。
//
// 用 127.0.0.1:9 而不是一个域名：startVPN 的构造与拆卸都是惰性的（tailcat 到 DERP
// 的连接在后台按退避重试），因此用例既不需要网络也不会等超时，同时避免在测试里做
// 真实 DNS 查询。
const vpnTestDERPAddr = "127.0.0.1:9"

// vpnTestConfig 返回一份启用了 VPN 的客户端配置，它的 DERP 指向本机一个没人监听的
// 端口。

func vpnTestConfig() *config.ClientConfig {
	return &config.ClientConfig{
		Servers: []*config.ServerProfile{{
			Address:  "127.0.0.1",
			Port:     9,
			Password: "test",
			Method:   sharedconfig.DefaultMethod,
			DERP:     true,
		}},
		Local: config.LocalConfig{SocksPort: sharedconfig.DefaultSocksPort},
		VPN:   config.VPNConfig{Enabled: true},
	}
}

func vpnTestTimeouts() sharedconfig.Timeouts {
	return sharedconfig.Timeouts{Base: 30 * time.Second, Dial: 5 * time.Second, StreamIdle: 30 * time.Second}
}

// TestStartVPNBuildsAStackAndStopsCleanly 固定 runner 侧的组装契约：一条调用就能
// 建起对端面、访问侧与发布地址，而 close 幂等。
func TestStartVPNBuildsAStackAndStopsCleanly(t *testing.T) {
	paths := vpnTestPaths(t)
	stack, err := startVPN(vpnTestConfig(), vpnTestTimeouts(), paths, false)
	if err != nil {
		t.Fatalf("startVPN: %v", err)
	}
	if stack.face == nil || stack.clients == nil || stack.route == nil {
		t.Fatalf("startVPN returned an incomplete stack: %+v", stack)
	}

	// 三个状态文件都必须落盘：两份长期密钥（身份）与一份给运维复制的地址。
	for _, p := range []string{paths.nodeIdentity, paths.clientKey, paths.peerAddr} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("state file %s: %v", p, err)
		}
	}
	// peer.txt 里必须是**完整展开格式**的地址：它是运维复制到各访问侧的唯一来源，
	// 一份短格式地址会让每个对端都去拉官方 DERPMap（见 docs/vpn-design.md 4.7）。
	content, err := os.ReadFile(paths.peerAddr)
	if err != nil {
		t.Fatalf("read %s: %v", paths.peerAddr, err)
	}
	addr := strings.TrimSpace(string(content))
	if err := vpnnode.AssertFullAddr(addr); err != nil {
		t.Fatalf("the published address is not usable by peers: %v", err)
	}

	if err := stack.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// 幂等：托盘的关闭流程与更新重启路径可能各调一次。
	if err := stack.close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	// nil 安全：没有启用 VPN 的会话上 StopVPN 是空操作。
	(&Core{}).StopVPN()
}

// TestStopVPNLeavesNoGoroutines 固定"关闭时零 goroutine"：tailcat 的 Server 会拉起
// WireGuard 引擎、netmon 与 magicsock，它们的收尾是异步的，因此这里给一个有界的
// 稳定窗口，而不是断言"立刻归零"。
func TestStopVPNLeavesNoGoroutines(t *testing.T) {
	// 先让测试框架自身的 goroutine 稳定下来，再取基线。
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	stack, err := startVPN(vpnTestConfig(), vpnTestTimeouts(), vpnTestPaths(t), false)
	if err != nil {
		t.Fatalf("startVPN: %v", err)
	}
	// 前提校验：VPN 栈确实拉起了自己的 goroutine（WireGuard 引擎、magicsock、
	// netmon）。否则这条用例只是在断言"什么都没发生"。
	if running := runtime.NumGoroutine(); running <= baseline {
		t.Fatalf("goroutines after startVPN = %d, baseline %d: the stack did not start anything, so this case proves nothing",
			running, baseline)
	}
	core := &Core{}
	core.vpn = stack
	core.StopVPN()

	deadline := time.Now().Add(15 * time.Second)
	for {
		runtime.GC()
		got := runtime.NumGoroutine()
		if got <= baseline+2 {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			n := runtime.Stack(buf, true)
			t.Fatalf("goroutines after StopVPN = %d, want <= %d (baseline %d): the vpn stack leaked\n%s",
				got, baseline+2, baseline, buf[:n])
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestLoadVPNIdentity 固定 CLI 输出的两半：client nodekey 不依赖任何配置，地址则
// 需要能推导出 DERP 位置。
func TestLoadVPNIdentity(t *testing.T) {
	paths := vpnTestPaths(t)
	id, err := loadVPNIdentity(vpnTestConfig(), paths)
	if err != nil {
		t.Fatalf("loadVPNIdentity: %v", err)
	}
	if !strings.HasPrefix(id.ClientNodeKey, "nodekey:") {
		t.Fatalf("client nodekey = %q, want a nodekey:... string (that is the format vpn.allow_clients parses)", id.ClientNodeKey)
	}
	if id.AddrErr != nil {
		t.Fatalf("AddrErr = %v, want nil", id.AddrErr)
	}
	if err := vpnnode.AssertFullAddr(id.TailcatAddr); err != nil {
		t.Fatalf("LoadVPNIdentity handed out an unusable address: %v", err)
	}

	// 同一份路径必须给出同一把 key：allow_clients 白名单的前提是它跨重启稳定。
	again, err := loadVPNIdentity(vpnTestConfig(), paths)
	if err != nil {
		t.Fatalf("loadVPNIdentity again: %v", err)
	}
	if again.ClientNodeKey != id.ClientNodeKey {
		t.Fatal("the client nodekey changed between calls; every peer's allow_clients entry would stop matching")
	}
	if again.TailcatAddr != id.TailcatAddr {
		t.Fatal("the node address changed between calls; every peer's vpn.peers[].address would need an update")
	}

	// 地址不依赖 peers：运维第一次跑这条命令时 peers 往往正是空的（他们要先拿到
	// 对端地址才能填）。一个写坏的 peer 地址不能让地址部分变得不可用。
	broken := vpnTestConfig()
	broken.VPN.Peers = []config.VPNPeer{{HostName: "b", Address: "not-a-tailcat-address"}}
	withBrokenPeer, err := loadVPNIdentity(broken, vpnTestPaths(t))
	if err != nil {
		t.Fatalf("loadVPNIdentity with a broken peer: %v", err)
	}
	if withBrokenPeer.AddrErr != nil {
		t.Fatalf("AddrErr = %v although the node address does not depend on vpn.peers", withBrokenPeer.AddrErr)
	}
	if withBrokenPeer.TailcatAddr == "" {
		t.Fatal("the node address is unavailable with an unfilled/broken peers entry")
	}
}

// TestLoadVPNIdentityWithoutDERPAddr 固定降级行为：推导不出 DERP 位置时，地址部分
// 给出原因而不是让整条命令失败——client nodekey 不依赖配置，而它正是"白名单配不起来"
// 时最需要先拿到的东西。
func TestLoadVPNIdentityWithoutDERPAddr(t *testing.T) {
	cfg := vpnTestConfig()
	cfg.Servers = nil
	cfg.VPN.DERPAddr = ""

	id, err := loadVPNIdentity(cfg, vpnTestPaths(t))
	if err != nil {
		t.Fatalf("loadVPNIdentity: %v", err)
	}
	if id.ClientNodeKey == "" {
		t.Fatal("the client nodekey is unavailable even though it does not depend on the config")
	}
	if id.AddrErr == nil {
		t.Fatal("AddrErr is nil although no DERP host:port can be derived")
	}
}

// TestVPNOptionsRequiresDERPAddr 固定严格失败：一个启用了 VPN 却没有可推导 DERP
// 位置的配置必须在启动阶段报错，而不是让节点带着一个错的地址跑起来。
func TestVPNOptionsRequiresDERPAddr(t *testing.T) {
	if _, err := vpnOptions(&config.ClientConfig{VPN: config.VPNConfig{Enabled: true}}); err == nil {
		t.Fatal("vpnOptions accepted a config without a derivable DERP host:port")
	}
}

// TestVPNPathsAreUnderTheExecutableDir 固定生产路径的形状：密钥与地址文件都落在
// <exe>/vpn/ 下（与 config.json、日志同目录），这样"备份/迁移一个节点"只需要带走
// 一个目录。
func TestVPNPathsAreUnderTheExecutableDir(t *testing.T) {
	paths := defaultVPNPaths()
	for name, p := range map[string]string{
		"node identity": paths.nodeIdentity,
		"client key":    paths.clientKey,
		"peer address":  paths.peerAddr,
	} {
		if !strings.HasPrefix(p, vpn.StateDir()) {
			t.Errorf("%s path %q is not under the vpn state dir %q", name, p, vpn.StateDir())
		}
	}
}

// vpnTestPeer 造一个真实的对端引用：地址由 vpn.BuildRegion 与一个临时身份生成，
// 因此它是完整展开格式，且内嵌的 DERP 主机就是传入的 derpAddr——DERP 私有化要求
// 它与本节点通告的地址一致（见 vpnnode.assertPeersShareDERP）。
func vpnTestPeer(t *testing.T, derpAddr string) config.VPNPeer {
	t.Helper()

	region, err := vpn.BuildRegion(derpAddr)
	if err != nil {
		t.Fatalf("vpn.BuildRegion(%q): %v", derpAddr, err)
	}
	identity, err := vpnnode.LoadOrCreateNodeIdentity(filepath.Join(t.TempDir(), "peer-identity.json"))
	if err != nil {
		t.Fatalf("LoadOrCreateNodeIdentity: %v", err)
	}
	return config.VPNPeer{HostName: "b", Address: identity.Address(region)}
}

// TestStartVPNForcesRelayOnlyUnderTun 固定 8.1 的强制：TUN 打开时 relay_only=false
// 的配置必须在本会话强制为 true，而且必须发生在任何 tailcat 组件启动**之前**。
//
// 这是唯一真正生效的时机：tailscale 的开关是 magicsock 建 socket 时读的，之后
// 再置 true 对已绑好的 UDP socket 没有作用（见 vpnnode.ApplyRelayOnly）。
func TestStartVPNForcesRelayOnlyUnderTun(t *testing.T) {
	t.Cleanup(func() { vpnnode.ApplyRelayOnly(false) })

	off := false
	for _, tc := range []struct {
		name     string
		tun      bool
		relay    *bool
		peers    int
		wantOnly bool
	}{
		{name: "no tun keeps the configured relay_only=false", tun: false, relay: &off, peers: 1, wantOnly: false},
		{name: "tun forces relay_only on", tun: true, relay: &off, peers: 1, wantOnly: true},
		{name: "no peer means no direct path to disable", tun: true, relay: &off, peers: 0, wantOnly: false},
		{name: "an explicit relay_only=true is preserved", tun: true, relay: nil, peers: 1, wantOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := vpnTestConfig()
			cfg.VPN.RelayOnly = tc.relay
			if tc.peers > 0 {
				cfg.VPN.Peers = []config.VPNPeer{vpnTestPeer(t, vpnTestDERPAddr)}
			}

			stack, err := startVPN(cfg, vpnTestTimeouts(), vpnTestPaths(t), tc.tun)
			if err != nil {
				t.Fatalf("startVPN: %v", err)
			}
			t.Cleanup(func() { _ = stack.close() })

			if stack.relayOnly != tc.wantOnly {
				t.Errorf("stack.relayOnly = %v, want %v", stack.relayOnly, tc.wantOnly)
			}
			// 生效的开关必须与栈记录的一致：只改记录而不写 tailscale 的开关
			// 会让日志与真实数据面互相矛盾。
			if got := envknob.Bool(vpnnode.RelayOnlyEnvKnob); got != tc.wantOnly {
				t.Errorf("%s = %v, want %v", vpnnode.RelayOnlyEnvKnob, got, tc.wantOnly)
			}
		})
	}
}

// TestCheckVPNTunCompat 固定运行期门禁：只有在"VPN 已启用 + relay_only 关闭 +
// 确实配置了对端"三者同时成立时才拒绝 TUN，因为此时直连报文会被 TUN 捕获并绕回
// easyss 自己的 SOCKS5（见 docs/vpn-design.md 8.1）。
func TestCheckVPNTunCompat(t *testing.T) {
	for _, tc := range []struct {
		name    string
		core    *Core
		wantErr bool
	}{
		{name: "no vpn", core: &Core{}, wantErr: false},
		{name: "relay only on", core: &Core{vpn: &vpnStack{relayOnly: true, peers: 2}}, wantErr: false},
		{name: "no peers", core: &Core{vpn: &vpnStack{relayOnly: false, peers: 0}}, wantErr: false},
		{name: "direct connections with peers", core: &Core{vpn: &vpnStack{relayOnly: false, peers: 1}}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.core.CheckVPNTunCompat()
			if tc.wantErr && err == nil {
				t.Fatal("CheckVPNTunCompat allowed TUN although direct peer connections are enabled")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("CheckVPNTunCompat = %v, want nil", err)
			}
		})
	}

	// nil 核心（未启动的会话）必须安全。
	var nilCore *Core
	if err := nilCore.CheckVPNTunCompat(); err != nil {
		t.Fatalf("CheckVPNTunCompat on a nil core = %v, want nil", err)
	}
}

// TestRunDegradesWhenVPNFailsToStart 固定"VPN 是可选功能"这条运行期契约：VPN 配置
// 写错（这里是对端地址非法）时基础代理必须照常起来，并把原因作为启动警告交给调用方
// （托盘据此提示），而不是把整个客户端拖死。
func TestRunDegradesWhenVPNFailsToStart(t *testing.T) {
	cfg := testConfig()
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0
	cfg.VPN.Enabled = true
	cfg.VPN.Peers = []config.VPNPeer{{HostName: "b", Address: "not-a-tailcat-address"}}

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run must keep the proxy running when only the VPN failed: %v", err)
	}
	t.Cleanup(core.Stop)

	if core.vpn != nil {
		t.Error("a failed VPN start must not leave a stack behind")
	}
	if core.derpShim != nil {
		t.Error("a failed VPN start must not leave the DERP entry behind")
	}
	if core.StartupWarn == nil {
		t.Fatal("the failure must be surfaced as a startup warning")
	}
	if !strings.Contains(core.StartupWarn.Error(), "invalid tailcat address") {
		t.Errorf("the startup warning must name the cause, got: %v", core.StartupWarn)
	}
	if core.SocksServer == nil {
		t.Error("the SOCKS5 entry must still be running")
	}
}
