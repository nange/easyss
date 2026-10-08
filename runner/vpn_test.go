package runner

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/envknob"

	"github.com/nange/easyss/v3/client/config"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
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

// vpnTestDERPAddrs 是测试配置里本节点通告、且所有对端也必须通告的 DERP 节点集合
// （DERP 私有化要求双方声明同一组中继，见 vpnnode.assertPeersShareDERPSet）。
//
// 用 127.0.0.1:9 / 127.0.0.2:9 而不是域名：startVPN 的构造与拆卸都是惰性的
// （tailcat 到 DERP 的连接在后台按退避重试），因此用例既不需要网络也不会等超时，
// 同时避免在测试里做真实 DNS 查询。
var vpnTestDERPAddrs = []string{"127.0.0.1:9", "127.0.0.2:9"}

// vpnTestConfig 返回一份启用了 VPN 的客户端配置：两条服务端条目都标记了 derp，
// 因此本节点地址里是两个中继节点（同 region 多节点形态），它们的地址都指向本机
// 没人监听的端口（构造与拨号都是惰性的）。
//
// default 标记落在第一条上：需求 4 要求"当前服务端必须在声明的中继列表里"，
// 否则 VPN 会在启动时被拒绝。
func vpnTestConfig() *config.ClientConfig {
	return &config.ClientConfig{
		Servers: []*config.ServerProfile{
			{Address: "127.0.0.1", Port: 9, Password: "test", Method: sharedconfig.DefaultMethod, DERP: true, Default: true},
			{Address: "127.0.0.2", Port: 9, Password: "test", Method: sharedconfig.DefaultMethod, DERP: true},
		},
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
	stack, err := startVPN(vpnTestConfig(), vpnTestTimeouts(), paths, false, nil)
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
	// 一份短格式地址会让每个对端都去拉官方 DERPMap。
	content, err := os.ReadFile(paths.peerAddr)
	if err != nil {
		t.Fatalf("read %s: %v", paths.peerAddr, err)
	}
	addr := strings.TrimSpace(string(content))
	if err := vpnnode.AssertFullAddr(addr); err != nil {
		t.Fatalf("the published address is not usable by peers: %v", err)
	}
	// 两个被 derp 标记的服务端都必须出现在同一 region 里（多中继节点）。
	ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		t.Fatalf("parse the published address: %v", err)
	}
	if len(ci.Region) != 1 || len(ci.Region[0].Nodes) != 2 {
		t.Fatalf("published address carries %d regions with %d nodes, want one region with 2 relays", len(ci.Region), len(ci.Region[0].Nodes))
	}
	hosts := []string{ci.Region[0].Nodes[0].HostName, ci.Region[0].Nodes[1].HostName}
	if !slices.Equal(hosts, []string{"127.0.0.1", "127.0.0.2"}) {
		t.Errorf("published relay hosts = %v, want [127.0.0.1 127.0.0.2] in config order", hosts)
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

	stack, err := startVPN(vpnTestConfig(), vpnTestTimeouts(), vpnTestPaths(t), false, nil)
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
	// 声明的两个中继都必须出现在地址里，并且 DERPNodes 与地址内容一致（运维靠这
	// 一行判断"地址里到底有几个中继"）。
	if want := []string{"127.0.0.1:9", "127.0.0.2:9"}; !slices.Equal(id.DERPNodes, want) {
		t.Errorf("DERPNodes = %v, want %v", id.DERPNodes, want)
	}
	ci, err := tailcat.ParseAddr(tailcat.Addr(id.TailcatAddr))
	if err != nil {
		t.Fatalf("parse the identity address: %v", err)
	}
	if len(ci.Region) != 1 || len(ci.Region[0].Nodes) != 2 {
		t.Fatalf("identity address carries %d regions with %d nodes, want one region with 2 relays", len(ci.Region), len(ci.Region[0].Nodes))
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

// lockedLogBuffer 是并发安全的日志缓冲。
//
// 断言发生在测试 goroutine 上，而 VPN 栈一启动就有后台 goroutine 在写日志（对端面的
// SOCKS5 的 "serving"、tailcat 的 DERP 重试等）：用裸 bytes.Buffer 会被 -race 判成
// 数据竞争——Windows CI 上已经实测命中过一次。
type lockedLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedLogBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLogs 把 easyss 的日志器换成写入 lockedLogBuffer 的 slog，并返回该缓冲与
// 恢复函数（恢复由 t.Cleanup 完成）。日志器本身的换装是原子的（见 log.SetLogger），
// 唯一需要测试自己保证的是 sink 的并发安全。
func captureLogs(t *testing.T) *lockedLogBuffer {
	t.Helper()
	buf := new(lockedLogBuffer)
	prev := log.Logger()
	log.SetLogger(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { log.SetLogger(prev) })
	return buf
}

// TestStartVPNDoesNotLogTheAddress 是"地址令牌不进日志"的守门测试。
//
// tailcat 地址内嵌 preshared key，等价于对端面的接入凭据，而日志文件长期留存、
// 经常被整体打包带走。启动路径因此只记录 address_file（文件路径）与不含秘密的
// 中继列表，地址本身只经 `-show-vpn-identity` 与本地文件交付。
func TestStartVPNDoesNotLogTheAddress(t *testing.T) {
	logs := captureLogs(t)

	paths := vpnTestPaths(t)
	stack, err := startVPN(vpnTestConfig(), vpnTestTimeouts(), paths, false, nil)
	if err != nil {
		t.Fatalf("startVPN: %v", err)
	}
	t.Cleanup(func() { _ = stack.close() })

	content, err := os.ReadFile(paths.peerAddr)
	if err != nil {
		t.Fatalf("read %s: %v", paths.peerAddr, err)
	}
	addr := strings.TrimSpace(string(content))
	if addr == "" {
		t.Fatal("the published address is empty; this test would not prove anything")
	}

	out := logs.String()
	if out == "" {
		t.Fatal("startVPN logged nothing; the assertion below would be vacuous")
	}
	if strings.Contains(out, addr) {
		t.Errorf("the startup log contains the tailcat address (it embeds the preshared key):\n%s", out)
	}
	// 地址总以 "tc" 开头，用裸前缀再挡一次：即便地址被截断/改写，也不该有任何
	// 前缀形态出现在日志里。阈值取 16 个字符是为了不误伤 tcp/目标地址之类的普通词。
	if tailcatAddrInLog.MatchString(out) {
		t.Errorf("the startup log contains something shaped like a tailcat address:\n%s", out)
	}
	if !strings.Contains(out, "address_file") {
		t.Errorf("the startup log does not point at the address file, so the operator has no way to find the address:\n%s", out)
	}
	if !strings.Contains(out, "derp_addrs") {
		t.Errorf("the startup log does not name the declared relays:\n%s", out)
	}
}

// tailcatAddrInLog 匹配"看起来像 tailcat 地址"的 token：tc + 至少 16 个 base64url
// 字符。真实地址远长于此，而 tcp、target 这类普通词后面跟不出这么长的连续 base64url。
var tailcatAddrInLog = regexp.MustCompile(`\btc[A-Za-z0-9_-]{16,}`)

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

// TestLoadVPNIdentityIgnoresTheCurrentServerCheck 固定 `-show-vpn-identity` 的
// 定位：它是排障工具，**不**执行"当前服务端必须在声明的中继列表里"这道 VPN 启动
// 门禁（否则运维在最需要地址的时候反而拿不到地址）。该问题由调用方作为一行 warning
// 打给用户，而 VPN 是否启动由 vpnOptions 决定。
func TestLoadVPNIdentityIgnoresTheCurrentServerCheck(t *testing.T) {
	cfg := vpnTestConfig()
	// 当前服务端换成一条没有被 derp 标记的条目：VPN 会拒绝启动，但地址仍然要能拿到。
	cfg.Servers = append(cfg.Servers, &config.ServerProfile{
		Address: "127.0.0.3", Port: 9, Password: "test", Method: sharedconfig.DefaultMethod, Default: true,
	})
	for _, srv := range cfg.Servers[:2] {
		srv.Default = false
	}

	if err := cfg.ValidateDERPServer(); err == nil {
		t.Fatal("ValidateDERPServer() = nil, want an error for an unmarked current server")
	}
	if _, err := vpnOptions(cfg); err == nil {
		t.Fatal("vpnOptions accepted a config whose current server is not a declared relay")
	}

	id, err := loadVPNIdentity(cfg, vpnTestPaths(t))
	if err != nil {
		t.Fatalf("loadVPNIdentity: %v", err)
	}
	if id.AddrErr != nil {
		t.Fatalf("AddrErr = %v, want nil: the address must stay available for troubleshooting", id.AddrErr)
	}
	if !slices.Equal(id.DERPNodes, []string{"127.0.0.1:9", "127.0.0.2:9"}) {
		t.Errorf("DERPNodes = %v, want the two marked relays", id.DERPNodes)
	}
}

// TestVPNOptionsRequiresDERPAddr 固定严格失败：一个启用了 VPN 却没有可推导 DERP
// 位置的配置必须在启动阶段报错，而不是让节点带着一个错的地址跑起来。
func TestVPNOptionsRequiresDERPAddr(t *testing.T) {
	if _, err := vpnOptions(&config.ClientConfig{VPN: config.VPNConfig{Enabled: true}}); err == nil {
		t.Fatal("vpnOptions accepted a config without a derivable DERP host:port")
	}
}

// TestVPNOptionsRejectsUndeclaredCurrentServer 固定需求 4 的门禁：当前服务端不在
// 声明的中继列表里时，VPN 必须在启动阶段被拒绝（由 runCore 记 ERROR、并入
// StartupWarn），而不是等到第一次访问对端时以"隧道拨号超时"的形式暴露——内嵌
// DERP 只接待经本服务端隧道送达的连接，声明列表里没有它时中继永远连不上。
func TestVPNOptionsRejectsUndeclaredCurrentServer(t *testing.T) {
	cfg := vpnTestConfig()
	cfg.Servers = append(cfg.Servers, &config.ServerProfile{
		Address: "127.0.0.3", Port: 9, Password: "test", Method: sharedconfig.DefaultMethod, Default: true,
	})
	for _, srv := range cfg.Servers[:2] {
		srv.Default = false
	}

	_, err := vpnOptions(cfg)
	if err == nil {
		t.Fatal("vpnOptions accepted a current server that is not a declared DERP relay")
	}
	for _, want := range []string{"127.0.0.3:9", "127.0.0.1:9", "derp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}

	// 把那条服务端也标记成中继之后必须通过：这是给用户的修复动作。
	cfg.Servers[2].DERP = true
	if _, err := vpnOptions(cfg); err != nil {
		t.Fatalf("vpnOptions rejected the fixed config: %v", err)
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
// 因此它是完整展开格式，且内嵌的 DERP 主机就是传入的 derpAddrs——DERP 私有化要求
// 它与本节点通告的地址集合一致（见 vpnnode.assertPeersShareDERPSet）。
func vpnTestPeer(t *testing.T, derpAddrs ...string) config.VPNPeer {
	t.Helper()

	region, err := vpn.BuildRegion(derpAddrs...)
	if err != nil {
		t.Fatalf("vpn.BuildRegion(%q): %v", derpAddrs, err)
	}
	identity, err := vpnnode.LoadOrCreateNodeIdentity(filepath.Join(t.TempDir(), "peer-identity.json"))
	if err != nil {
		t.Fatalf("LoadOrCreateNodeIdentity: %v", err)
	}
	return config.VPNPeer{HostName: "b", Address: identity.Address(region)}
}

// derpOnlyEnvKnob 是 tailcat 的 DERPOnly 写进去的那个 tailscale 开关（见 tailcat
// 的 createEngine）。测试直接盯它，是为了保证"会话记录的 relay_only"与"真正生效的
// 数据面开关"一致，而不是只改前者。
const derpOnlyEnvKnob = "TS_DEBUG_ALWAYS_USE_DERP"

// TestStartVPNForcesRelayOnlyUnderTun 固定 8.1 的强制：TUN 打开时 relay_only=false
// 的配置必须在本会话强制为 true，而且必须发生在 tailcat 创建引擎**之前**。
//
// 这是唯一真正生效的时机：tailscale 的开关是 magicsock 建 socket 时读的，之后
// 再置 true 对已绑好的 UDP socket 没有作用（见 tailcat 的 DERPOnly 选项）。
func TestStartVPNForcesRelayOnlyUnderTun(t *testing.T) {
	t.Cleanup(func() { envknob.Setenv(derpOnlyEnvKnob, "false") })

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
				cfg.VPN.Peers = []config.VPNPeer{vpnTestPeer(t, vpnTestDERPAddrs...)}
			}

			stack, err := startVPN(cfg, vpnTestTimeouts(), vpnTestPaths(t), tc.tun, nil)
			if err != nil {
				t.Fatalf("startVPN: %v", err)
			}
			t.Cleanup(func() { _ = stack.close() })

			if stack.relayOnly != tc.wantOnly {
				t.Errorf("stack.relayOnly = %v, want %v", stack.relayOnly, tc.wantOnly)
			}
			// 生效的开关必须与栈记录的一致：只改记录而不写 tailscale 的开关
			// 会让日志与真实数据面互相矛盾。
			if got := envknob.Bool(derpOnlyEnvKnob); got != tc.wantOnly {
				t.Errorf("%s = %v, want %v", derpOnlyEnvKnob, got, tc.wantOnly)
			}
		})
	}
}

// TestCheckVPNTunCompat 固定运行期门禁：只有在"VPN 已启用 + relay_only 关闭 +
// 确实配置了对端"三者同时成立时才拒绝 TUN，因为此时直连报文会被 TUN 捕获并绕回
// easyss 自己的 SOCKS5。
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

// TestDotlessHostNames 固定"哪些对端名在 Windows 上注定解析不到"的判定：只看名字
// 里是否含点，与大小写、长度、位置无关，且保持配置顺序（日志按配置读）。
func TestDotlessHostNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		peers []vpnnode.PeerRef
		want  []string
	}{
		{name: "no peers", peers: nil, want: nil},
		{name: "every name has a dot", peers: []vpnnode.PeerRef{{HostName: "b.lan"}, {HostName: "easyss-mac.vpn"}}, want: nil},
		{name: "single label names in config order", peers: []vpnnode.PeerRef{{HostName: "easyss-mac"}, {HostName: "b.lan"}, {HostName: "NAS"}}, want: []string{"easyss-mac", "NAS"}},
		{name: "the root dot is already stripped by normalizePeers", peers: []vpnnode.PeerRef{{HostName: "b"}}, want: []string{"b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := dotlessHostNames(tc.peers)
			if !slices.Equal(got, tc.want) {
				t.Errorf("dotlessHostNames(%+v) = %v, want %v", tc.peers, got, tc.want)
			}
		})
	}
}

// TestWarnOnSingleLabelPeerNames 固定平台门控：Windows 上必须为无点的对端名打一条
// 警告（否则用户只看到"名字解析不了"，而日志里连一条 DNS 查询都没有），其他平台上
// 一条都不打——Linux/macOS 的解析器会把单标签名交给 DNS。
//
// 同时固定警告里点名的是**无点的那些**名字：一条笼统的警告对排障没有价值。
func TestWarnOnSingleLabelPeerNames(t *testing.T) {
	peers := []vpnnode.PeerRef{{HostName: "easyss-mac"}, {HostName: "b.lan"}, {HostName: "NAS"}}

	for _, tc := range []struct {
		name     string
		goos     string
		peers    []vpnnode.PeerRef
		wantWarn bool
	}{
		{name: "windows with a single label name", goos: "windows", peers: peers, wantWarn: true},
		{name: "windows with only dotted names", goos: "windows", peers: []vpnnode.PeerRef{{HostName: "b.lan"}}, wantWarn: false},
		{name: "windows without peers", goos: "windows", peers: nil, wantWarn: false},
		{name: "linux", goos: "linux", peers: peers, wantWarn: false},
		{name: "darwin", goos: "darwin", peers: peers, wantWarn: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)

			warnOnSingleLabelPeerNames(tc.goos, tc.peers)

			out := logs.String()
			if !tc.wantWarn {
				if out != "" {
					t.Fatalf("warnOnSingleLabelPeerNames(%q) logged %q, want nothing", tc.goos, out)
				}
				return
			}
			if !strings.Contains(out, "level=WARN") {
				t.Fatalf("the warning is not at WARN level: %q", out)
			}
			for _, name := range []string{"easyss-mac", "NAS"} {
				if !strings.Contains(out, name) {
					t.Errorf("the warning does not name the dotless peer %q: %q", name, out)
				}
			}
			if strings.Contains(out, "b.lan") {
				t.Errorf("the warning names a peer that has a dot and resolves fine: %q", out)
			}
			// 警告必须自带出路：用户看不懂"解析器不发单标签查询"时至少要能照做。
			if !strings.Contains(out, "dotted host_name") {
				t.Errorf("the warning does not tell the user what to do about it: %q", out)
			}
		})
	}
}

// TestStopVPNAbandonsAStuckStack 固定"关闭卡死时 StopVPN 也必须按时返回"。
//
// 这是退出路径（托盘"退出"）与服务器切换路径共用的拆除入口，而 tailcat →
// wireguard-go → magicsock 的关闭链上存在会永久阻塞的分支：无界等待的表现就是
// 托盘图标消失了、进程却永远不退出。这里注入一个永不返回的关闭过程，断言调用方
// 在 vpnCloseTimeout 之后仍能继续往下走（真实卡死现场见 vpnCloseTimeout 的注释）。
func TestStopVPNAbandonsAStuckStack(t *testing.T) {
	origClose, origTimeout := closeVPNStack, vpnCloseTimeout
	t.Cleanup(func() {
		closeVPNStack, vpnCloseTimeout = origClose, origTimeout
	})

	// 关闭过程永远不返回；测试结束时才放行，避免它成为永久泄漏的 goroutine。
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	closeVPNStack = func(*vpnStack) error {
		<-release
		return nil
	}
	vpnCloseTimeout = 50 * time.Millisecond

	core := &Core{}
	core.vpn = &vpnStack{}

	returned := make(chan struct{})
	go func() {
		core.StopVPN()
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("StopVPN did not return: a stuck vpn teardown must not block the caller forever")
	}
	if core.vpn != nil {
		t.Error("StopVPN must take the stack off the core even when closing it timed out")
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

// TestRunDegradesWhenTheCurrentServerIsNotADERPRelay 固定需求 4 在运行期的表现：
// 当前服务端不在声明的中继列表里时，日志里必须有一条 ERROR，VPN 本会话缺席，而
// 基础代理照常可用（与"VPN 是可选功能"的既有契约一致）。
func TestRunDegradesWhenTheCurrentServerIsNotADERPRelay(t *testing.T) {
	logs := captureLogs(t)

	cfg := testConfig()
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0
	cfg.VPN.Enabled = true
	// 一条被标记为中继、一条没有被标记却承担当前连接：后者必须让 VPN 拒绝启动。
	cfg.Servers = []*config.ServerProfile{
		{Address: "relay.example.com", Port: 443, Password: "test", Method: sharedconfig.DefaultMethod, DERP: true},
		{Address: "other.example.com", Port: 443, Password: "test", Method: sharedconfig.DefaultMethod, Default: true},
	}

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run must keep the proxy running when only the VPN failed: %v", err)
	}
	t.Cleanup(core.Stop)

	if core.vpn != nil {
		t.Error("the VPN must not start when the current server is not a declared relay")
	}
	if core.StartupWarn == nil {
		t.Fatal("the failure must be surfaced as a startup warning")
	}
	if !strings.Contains(core.StartupWarn.Error(), "other.example.com:443") {
		t.Errorf("the startup warning must name the current server, got: %v", core.StartupWarn)
	}
	if core.SocksServer == nil {
		t.Error("the SOCKS5 entry must still be running")
	}
	out := logs.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "other.example.com:443") {
		t.Errorf("the refusal must be logged at ERROR level and name the server, got:\n%s", out)
	}
}
