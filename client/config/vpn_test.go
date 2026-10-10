package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// TestDERPServers 固定"谁提供内嵌 DERP"的选择规则：所有被 derp 标记的条目都进
// 列表（配置顺序，它们共同构成同一 region 的多个中继）；没有任何条目标记时回退
// **当前连接的服务端**（default 标记，其次 servers[0]），不再固定取 servers[0]。
//
// 回退到当前服务端是必要的：内嵌 DERP 只接待经本服务端隧道送达的连接，所以节点
// 实际能用的中继永远是它此刻连的那台；固定取 servers[0] 会在默认 server 不是第一
// 条时派生出一个永远连不上的中继。
func TestDERPServers(t *testing.T) {
	t.Run("被标记的条目按配置顺序全部返回", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, Default: true},
			{Address: "b.example.com", Port: 443, DERP: true},
			{Address: "c.example.com", Port: 8443, DERP: true},
		}}
		got := cfg.DERPServers()
		if len(got) != 2 || got[0].Address != "b.example.com" || got[1].Address != "c.example.com" {
			t.Fatalf("DERPServers() = %v, want [b.example.com c.example.com] in config order", got)
		}
		// 单节点视图 = 列表第一个（既有调用点与日志用）。
		if first := cfg.DERPServer(); first == nil || first.Address != "b.example.com" {
			t.Fatalf("DERPServer() = %v, want b.example.com", first)
		}
	})

	t.Run("无标记时回退 default 标记而不是 servers[0]", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443},
			{Address: "b.example.com", Port: 443, Default: true},
		}}
		got := cfg.DERPServers()
		if len(got) != 1 || got[0].Address != "b.example.com" {
			t.Fatalf("DERPServers() = %v, want the current server b.example.com", got)
		}
	})

	t.Run("无标记且无 default 时回退 servers[0]", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443},
			{Address: "b.example.com", Port: 443},
		}}
		got := cfg.DERPServers()
		if len(got) != 1 || got[0].Address != "a.example.com" {
			t.Fatalf("DERPServers() = %v, want a.example.com (DefaultServer falls back to servers[0])", got)
		}
	})

	t.Run("没有服务端条目", func(t *testing.T) {
		if got := (&ClientConfig{}).DERPServers(); got != nil {
			t.Fatalf("DERPServers() = %v, want nil", got)
		}
		if got := (&ClientConfig{}).DERPServer(); got != nil {
			t.Fatalf("DERPServer() = %v, want nil", got)
		}
	})
}

// TestVPNDERPAddrs 固定通告列表的派生：由全部 `derp: true` 标记条目派生（一条
// 都没有时是当前连接的服务端）；返回值必须是 host:port（IPv6 带方括号）、规范化
// 去重且保持配置顺序（对端会按这个顺序尝试中继节点）。
//
// 没有"显式覆盖"的入口是有意的：地址里内嵌的位置必须与服务端的对外地址逐字
// 一致，多节点只能靠多标记几条 `derp: true`。
func TestVPNDERPAddrs(t *testing.T) {
	t.Run("多标记派生多个节点并保持顺序", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Address: "a.example.com", Port: 443, Default: true},
				{Address: "relay.example.com", Port: 9443, DERP: true},
				{Address: "backup.example.com", Port: 443, DERP: true},
			},
		}
		got := cfg.VPNDERPAddrs()
		want := []string{"relay.example.com:9443", "backup.example.com:443"}
		if !slices.Equal(got, want) {
			t.Errorf("VPNDERPAddrs() = %v, want %v", got, want)
		}
		if first := cfg.VPNDERPAddr(); first != want[0] {
			t.Errorf("VPNDERPAddr() = %q, want the first node %q", first, want[0])
		}
	})

	t.Run("同一中继的不同书写只算一个节点", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Address: "relay.example.com", Port: 443, DERP: true},
				{Address: "Relay.Example.com", Port: 443, DERP: true},
			},
		}
		got := cfg.VPNDERPAddrs()
		if len(got) != 1 || got[0] != "relay.example.com:443" {
			t.Errorf("VPNDERPAddrs() = %v, want a single relay.example.com:443", got)
		}
	})

	t.Run("未配置且无标记时取当前服务端", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Address: "a.example.com", Port: 443},
				{Address: "b.example.com", Port: 443, Default: true},
			},
		}
		if got, want := cfg.VPNDERPAddr(), "b.example.com:443"; got != want {
			t.Errorf("VPNDERPAddr() = %q, want %q (the current server)", got, want)
		}
	})

	t.Run("没有服务端条目时为空", func(t *testing.T) {
		if got := (&ClientConfig{}).VPNDERPAddrs(); got != nil {
			t.Errorf("VPNDERPAddrs() = %v, want nil", got)
		}
		if got := (&ClientConfig{}).VPNDERPAddr(); got != "" {
			t.Errorf("VPNDERPAddr() = %q, want empty", got)
		}
	})

	t.Run("端口未设置时用默认端口", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{{Address: "a.example.com"}}}
		if got, want := cfg.VPNDERPAddr(), "a.example.com:443"; got != want {
			t.Errorf("VPNDERPAddr() = %q, want %q", got, want)
		}
	})

	t.Run("IPv6 字面量带方括号", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{{Address: "2001:db8::1", Port: 443}},
		}
		if got, want := cfg.VPNDERPAddr(), "[2001:db8::1]:443"; got != want {
			t.Errorf("VPNDERPAddr() = %q, want %q", got, want)
		}
	})
}

// TestValidateDERPServerAddr 固定"当前在运行的服务端必须是声明的中继之一"这条不变量：
// 内嵌 DERP 只接待经本服务端隧道送达的连接，声明列表里没有它时中继永远连不上，因此
// VPN 必须在启动阶段拒绝（见 runner.vpnOptions）而不是让用户看到"连不上"。
//
// 判据的入参是显式的：正在跑的会话可能停在旧的那台上，而 default 标记早已被托盘切换
// 改写，所以判定绝不能隐式取 DefaultServer（见下面"只看传进来的服务器"那条）。
func TestValidateDERPServerAddr(t *testing.T) {
	t.Run("当前服务端在列表里", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, DERP: true},
			{Address: "b.example.com", Port: 443, DERP: true, Default: true},
		}}
		if err := cfg.ValidateDERPServerAddr("b.example.com:443"); err != nil {
			t.Errorf("ValidateDERPServerAddr() = %v, want nil", err)
		}
	})

	t.Run("大小写不同不算不匹配", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "RELAY.example.com", Port: 443, DERP: true},
			{Address: "relay.example.com", Port: 443, Default: true},
		}}
		if err := cfg.ValidateDERPServerAddr(cfg.DefaultServer().HostPort()); err != nil {
			t.Errorf("ValidateDERPServerAddr() = %v, want nil: the two entries are the same relay", err)
		}
	})

	t.Run("当前服务端不在列表里时报错并点名双方", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, DERP: true},
			{Address: "b.example.com", Port: 443, DERP: true},
			{Address: "c.example.com", Port: 443, Default: true},
		}}
		err := cfg.ValidateDERPServerAddr("c.example.com:443")
		if err == nil {
			t.Fatal("ValidateDERPServerAddr() = nil, want an error for an unmarked current server")
		}
		if !errors.Is(err, ErrCurrentServerNotDERPRelay) {
			t.Errorf("the refusal must carry ErrCurrentServerNotDERPRelay so the tray can tell the user, got: %v", err)
		}
		for _, want := range []string{"c.example.com:443", "a.example.com:443", "b.example.com:443", "derp"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should mention %q", err, want)
			}
		}
	})

	t.Run("只看传进来的服务器，不看 default 标记", func(t *testing.T) {
		// default 在 b 上，但会话实际跑在 a 上（托盘刚切换、或回滚还没落地）：判定必须
		// 跟着传进来的那台走。反过来说，若谁把入参换成隐式的 DefaultServer()，这里就会
		// 在 a 在列表里时误报"当前服务端不在列表里"。
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, DERP: true},
			{Address: "b.example.com", Port: 443, DERP: true, Default: true},
			{Address: "c.example.com", Port: 443},
		}}
		if err := cfg.ValidateDERPServerAddr("a.example.com:443"); err != nil {
			t.Errorf("a is a declared relay: %v", err)
		}
		if err := cfg.ValidateDERPServerAddr("b.example.com:443"); err != nil {
			t.Errorf("b is a declared relay: %v", err)
		}
		if err := cfg.ValidateDERPServerAddr("c.example.com:443"); !errors.Is(err, ErrCurrentServerNotDERPRelay) {
			t.Errorf("c is not a declared relay, want the refusal, got %v", err)
		}
	})

	t.Run("当前服务器未知时不做判定", func(t *testing.T) {
		// 没有会话、也没有服务器条目时"当前服务器"是未知的：未知不等于不匹配。
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, DERP: true},
		}}
		if err := cfg.ValidateDERPServerAddr(""); err != nil {
			t.Errorf("ValidateDERPServerAddr(\"\") = %v, want nil", err)
		}
	})

	t.Run("无标记时当前服务端就是列表本身", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443},
			{Address: "b.example.com", Port: 443, Default: true},
		}}
		if err := cfg.ValidateDERPServerAddr("b.example.com:443"); err != nil {
			t.Errorf("ValidateDERPServerAddr() = %v, want nil", err)
		}
	})

	t.Run("没有可用列表时不在这里报错", func(t *testing.T) {
		if err := (&ClientConfig{}).ValidateDERPServerAddr("a.example.com:443"); err != nil {
			t.Errorf("ValidateDERPServerAddr() = %v, want nil (the VPN start path reports the empty list)", err)
		}
	})

	t.Run("列表里的地址都非法时不在这里报错", func(t *testing.T) {
		// 被标记的条目地址里混进了方括号 → 派生出一个拆不开的 "[relay.example.com:443"；
		// 当前服务端本身是好的。这条配置真正的问题是"中继地址非法"，由 vpnnode.NewConfig
		// 带节点序号报出；说成"当前服务端不在列表里"会把人引向错误的修法。
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "[relay.example.com", Port: 443, DERP: true},
			{Address: "b.example.com", Port: 443, Default: true},
		}}
		if err := cfg.ValidateDERPServerAddr("b.example.com:443"); err != nil {
			t.Errorf("ValidateDERPServerAddr() = %v, want nil for an unparsable relay list", err)
		}
	})
}

// TestValidateDERPRelays 固定"同一 region 最多 3 台中继（推荐 1-2 台）"这条规模上限
// （见 sharedconfig.MaxVPNRelays）：mesh 是全互联，而节点地址里内嵌的正是这一组中继，
// 所以越限的配置没有可工作的形态——第 4 台既进不了地址，也没法与其余中继互通。因此
// 它必须在启动阶段（LoadConfig）就被拒绝，而不是降级成"VPN 连不上"。
//
// 计数口径与 VPNDERPAddrs 一致（规范化去重），且只在 vpn.enabled 时生效：未启用的
// VPN 不参与运行期，derp 标记此时没有任何效果。
func TestValidateDERPRelays(t *testing.T) {
	// relays 造一份"1 条当前服务端 + n 条 derp 标记"的 servers[]。
	relays := func(n int) []*ServerProfile {
		out := make([]*ServerProfile, 0, n+1)
		out = append(out, &ServerProfile{Address: "current.example.com", Port: 443, Default: true})
		for i := range n {
			out = append(out, &ServerProfile{
				Address: fmt.Sprintf("relay%d.example.com", i), Port: 443, DERP: true,
			})
		}
		return out
	}

	t.Run("上限内通过", func(t *testing.T) {
		for n := 1; n <= sharedconfig.MaxVPNRelays; n++ {
			cfg := &ClientConfig{VPN: VPNConfig{Enabled: true}, Servers: relays(n)}
			if err := cfg.ValidateDERPRelays(); err != nil {
				t.Errorf("%d relays: ValidateDERPRelays() = %v, want nil", n, err)
			}
		}
	})

	t.Run("超过上限时报错并点名中继", func(t *testing.T) {
		cfg := &ClientConfig{VPN: VPNConfig{Enabled: true}, Servers: relays(sharedconfig.MaxVPNRelays + 1)}
		err := cfg.ValidateDERPRelays()
		if err == nil {
			t.Fatal("ValidateDERPRelays() = nil, want a refusal for more relays than supported")
		}
		for _, want := range []string{
			`"derp": true`, "4 DERP relays", "at most 3 relays", "1-2",
			"relay0.example.com:443", "relay3.example.com:443",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should mention %q", err, want)
			}
		}
	})

	t.Run("同一中继的不同书写只算一个", func(t *testing.T) {
		// 同一个中继标记 4 遍（含大小写差异与缺省端口）仍然只有 1 台：计数必须与
		// VPNDERPAddrs 的去重口径一致，否则"重复条目"会被误判成"中继太多"。
		cfg := &ClientConfig{VPN: VPNConfig{Enabled: true}, Servers: []*ServerProfile{
			{Address: "relay.example.com", Port: 443, DERP: true},
			{Address: "RELAY.example.com", Port: 443, DERP: true},
			{Address: "Relay.Example.com", Port: 443, DERP: true},
			{Address: "relay.example.com", Port: 0, DERP: true},
			{Address: "relay.example.com", Port: 443},
		}}
		if err := cfg.ValidateDERPRelays(); err != nil {
			t.Errorf("ValidateDERPRelays() = %v, want nil: all five entries are the same relay", err)
		}
	})

	t.Run("未标记的条目不计数", func(t *testing.T) {
		cfg := &ClientConfig{VPN: VPNConfig{Enabled: true}, Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, Default: true},
			{Address: "b.example.com", Port: 443},
			{Address: "c.example.com", Port: 443},
			{Address: "d.example.com", Port: 443},
			{Address: "e.example.com", Port: 443},
		}}
		if err := cfg.ValidateDERPRelays(); err != nil {
			t.Errorf("ValidateDERPRelays() = %v, want nil without any derp mark", err)
		}
	})

	t.Run("vpn 未启用时不校验", func(t *testing.T) {
		cfg := &ClientConfig{VPN: VPNConfig{Enabled: false}, Servers: relays(sharedconfig.MaxVPNRelays + 2)}
		if err := cfg.ValidateDERPRelays(); err != nil {
			t.Errorf("ValidateDERPRelays() = %v, want nil while the VPN is disabled", err)
		}
	})

	t.Run("地址非法的条目不在这里报错", func(t *testing.T) {
		// 被标记的条目地址里混进了方括号 → 规范化失败。这些条目真正的问题是
		// "地址非法"（由 vpnnode.NewConfig 带节点序号报出），把它们算成"中继太多"
		// 会把人引向错误的修法。
		cfg := &ClientConfig{VPN: VPNConfig{Enabled: true}, Servers: []*ServerProfile{
			{Address: "[relay0.example.com", Port: 443, DERP: true},
			{Address: "[relay1.example.com", Port: 443, DERP: true},
			{Address: "[relay2.example.com", Port: 443, DERP: true},
			{Address: "[relay3.example.com", Port: 443, DERP: true},
			{Address: "", Port: 443, DERP: true},
		}}
		if err := cfg.ValidateDERPRelays(); err != nil {
			t.Errorf("ValidateDERPRelays() = %v, want nil: the real problem is an invalid address", err)
		}
	})
}

// TestServerProfileHostPort 固定"一条服务端的对外 host:port"的形态：访问侧拨号、
// DERP 中继比较与节点地址里通告的位置共用这一个字符串，IPv6 字面量必须是带方括号的。
func TestServerProfileHostPort(t *testing.T) {
	cases := []struct {
		name string
		srv  *ServerProfile
		want string
	}{
		{"显式端口", &ServerProfile{Address: "relay.example.com", Port: 9443}, "relay.example.com:9443"},
		{"端口缺失时回退默认端口", &ServerProfile{Address: "relay.example.com"}, "relay.example.com:443"},
		{"IPv6 字面量带方括号", &ServerProfile{Address: "2001:db8::1", Port: 443}, "[2001:db8::1]:443"},
		{"没有地址时为空", &ServerProfile{}, ""},
		{"nil 安全", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.srv.HostPort(); got != tc.want {
				t.Errorf("HostPort() = %q, want %q", got, tc.want)
			}
		})
	}

	// 与 VPNDERPAddrs 派生出的字符串必须逐字一致：同一条服务端在本节点通告的位置（写进
	// 对端地址）与门禁比较的那两个路径上不能出现两种写法。
	cfg := &ClientConfig{Servers: []*ServerProfile{{Address: "2001:db8::1", Port: 9443, DERP: true}}}
	if got, want := cfg.VPNDERPAddr(), cfg.DefaultServer().HostPort(); got != want {
		t.Errorf("VPNDERPAddr() = %q, HostPort() = %q: the advertised and compared forms must match", got, want)
	}
}

// TestVPNPeerPortDerivation 固定 peer_port 的派生放在了访问器上而不是
// applyDefaults 里：这样命令行覆盖（--local-port）改动 socks_port 之后，
// 未显式配置的 peer_port 会跟着变，而不是冻结在"按旧 socks_port 派生"的结果上。
func TestVPNPeerPortDerivation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Local.SocksPort = sharedconfig.DefaultSocksPort
	if got, want := cfg.VPNPeerPort(), sharedconfig.DefaultVPNPeerPort; got != want {
		t.Errorf("VPNPeerPort() = %d, want %d", got, want)
	}

	cfg.Local.SocksPort = 5000
	if got, want := cfg.VPNPeerPort(), 7000; got != want {
		t.Errorf("after changing socks_port, VPNPeerPort() = %d, want %d", got, want)
	}

	cfg.VPN.PeerPort = 12345
	if got, want := cfg.VPNPeerPort(), 12345; got != want {
		t.Errorf("explicit peer_port: VPNPeerPort() = %d, want %d", got, want)
	}

	// 应用简单模式覆盖（--local-port）之后仍然跟随。
	ApplySimpleOverrides(cfg, &sharedconfig.SimpleConfig{LocalPort: 6000})
	cfg.VPN.PeerPort = 0
	if got, want := cfg.VPNPeerPort(), 8000; got != want {
		t.Errorf("after ApplySimpleOverrides, VPNPeerPort() = %d, want %d", got, want)
	}
}

// TestLoadConfigWarnsOnRemovedOverlayCIDR 固定已移除字段的降级行为：overlay 段
// 现在是访问侧本地的实现常量（config.DefaultVPNOverlayCIDR），没有任何配置项指向它。
// 配置里残留的 vpn.overlay_cidr 是未知键（json.Unmarshal 直接忽略），既不影响
// 加载，也不会让启动失败，但必须在启动日志里说清楚——它可能正是运维"已经把这段
// 改成别的"的原因，而那段现在是死配置，实际生效的仍是常量。
func TestLoadConfigWarnsOnRemovedOverlayCIDR(t *testing.T) {
	logs := captureLogs(t)

	path := filepath.Join(t.TempDir(), "config.json")
	body := `{
		"version": 3,
		"servers": [{"address": "a.example.com", "port": 443, "password": "p", "default": true}],
		"vpn": {"enabled": true, "overlay_cidr": "10.9.0.0/24"}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.VPN.Enabled {
		t.Error("VPN.Enabled = false, want true: the removed key must not affect the rest of the vpn config")
	}

	out := logs.String()
	if !strings.Contains(out, "vpn.overlay_cidr was removed") {
		t.Errorf("the load log does not report the removed key:\n%s", out)
	}
	if !strings.Contains(out, "10.9.0.0/24") {
		t.Errorf("the load log does not name the ignored value:\n%s", out)
	}
	if !strings.Contains(out, sharedconfig.DefaultVPNOverlayCIDR) {
		t.Errorf("the load log does not name the range actually in use (%s):\n%s", sharedconfig.DefaultVPNOverlayCIDR, out)
	}
}

// TestLoadConfigWithoutOverlayCIDRKeyStaysQuiet 守护告警不误报：没有那个键的配置
// 不该出现任何相关日志（overlay 段是常量，正常的配置里本就不该提到它）。
func TestLoadConfigWithoutOverlayCIDRKeyStaysQuiet(t *testing.T) {
	logs := captureLogs(t)

	path := filepath.Join(t.TempDir(), "config.json")
	body := `{
		"version": 3,
		"servers": [{"address": "a.example.com", "port": 443, "password": "p", "default": true}],
		"vpn": {"enabled": true}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if out := logs.String(); strings.Contains(out, "overlay_cidr") {
		t.Errorf("the load log mentions overlay_cidr although the config does not use it:\n%s", out)
	}
}

// TestVPNRelayOnlyTriState 固定 relay_only 的三态语义：缺省为 true（默认姿态是
// 只经中继），显式 false 必须能表达出来，显式 true 与缺省等价。
func TestVPNRelayOnlyTriState(t *testing.T) {
	t.Run("缺省为 true", func(t *testing.T) {
		var v VPNConfig
		if !v.RelayOnlyEnabled() {
			t.Error("zero-value VPNConfig: RelayOnlyEnabled() = false, want true")
		}
	})
	t.Run("显式 false", func(t *testing.T) {
		no := false
		if (VPNConfig{RelayOnly: &no}).RelayOnlyEnabled() {
			t.Error("RelayOnly=false: RelayOnlyEnabled() = true, want false")
		}
	})
	t.Run("显式 true", func(t *testing.T) {
		yes := true
		if !(VPNConfig{RelayOnly: &yes}).RelayOnlyEnabled() {
			t.Error("RelayOnly=true: RelayOnlyEnabled() = false, want true")
		}
	})
}

// TestVPNConfigJSONRoundTrip 固定 vpn 键的 JSON 形态：缺省的 relay_only 不出现在
// 序列化结果里，而显式 false 必须被保留下来——否则"省略"与"显式关闭"在配置
// 往返（Clone、托盘改写）之后会互相混淆。
func TestVPNConfigJSONRoundTrip(t *testing.T) {
	t.Run("relay_only 缺省时省略", func(t *testing.T) {
		data, err := json.Marshal(VPNConfig{Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["relay_only"]; ok {
			t.Errorf("default relay_only should be omitted, got %s", data)
		}
	})

	t.Run("显式 false 被保留", func(t *testing.T) {
		no := false
		data, err := json.Marshal(VPNConfig{Enabled: true, RelayOnly: &no})
		if err != nil {
			t.Fatal(err)
		}
		var back VPNConfig
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatal(err)
		}
		if back.RelayOnly == nil || *back.RelayOnly {
			t.Fatalf("after round trip relay_only = %v, want explicit false (json %s)", back.RelayOnly, data)
		}
		if back.RelayOnlyEnabled() {
			t.Error("RelayOnlyEnabled() = true after round trip, want false")
		}
	})
}

// TestVPNConfigParsesFromJSON 固定配置文件里的 vpn 键能完整解析（字段名与
// README 一致），并守住 servers[].derp 的解析。
//
// JSON 里刻意不含 overlay_cidr：overlay 段没有配置项，这个测试同时也在证明
// "README 里列出的字段"就是可配置的全部。
func TestVPNConfigParsesFromJSON(t *testing.T) {
	cfg, err := ParseConfigJSON(`{
		"version": 3,
		"servers": [
			{"address": "a.example.com", "port": 443, "password": "p", "default": true},
			{"address": "relay.example.com", "port": 8443, "password": "p", "derp": true}
		],
		"vpn": {
			"enabled": true,
			"relay_only": false,
			"peer_port": 7000,
			"peers": [
				{"host_name": "b", "address": "tcFULL", "port": 6080}
			],
			"allow_clients": ["nodekey:abc"]
		}
	}`)
	if err != nil {
		t.Fatalf("ParseConfigJSON: %v", err)
	}

	if !cfg.VPN.Enabled {
		t.Error("VPN.Enabled = false, want true")
	}
	if cfg.VPN.RelayOnlyEnabled() {
		t.Error("VPN.RelayOnlyEnabled() = true, want false (explicit relay_only:false)")
	}
	if got, want := cfg.VPNPeerPort(), 7000; got != want {
		t.Errorf("VPNPeerPort() = %d, want %d", got, want)
	}
	if got, want := cfg.VPNDERPAddr(), "relay.example.com:8443"; got != want {
		t.Errorf("VPNDERPAddr() = %q, want %q", got, want)
	}
	if len(cfg.VPN.Peers) != 1 || cfg.VPN.Peers[0].HostName != "b" || cfg.VPN.Peers[0].Port != 6080 {
		t.Errorf("VPN.Peers = %+v, want one peer b:6080", cfg.VPN.Peers)
	}
	if got := cfg.VPN.AllowClients; len(got) != 1 || got[0] != "nodekey:abc" {
		t.Errorf("VPN.AllowClients = %v, want [nodekey:abc]", got)
	}
	if cfg.DERPServer() == nil || !cfg.DERPServer().DERP {
		t.Error("DERPServer() did not pick the derp-marked entry")
	}
}

// TestVPNDisabledHasNoEffect 守护"vpn 关闭时对既有配置零影响"：一份不含 vpn 键
// 的旧配置加载后行为与今天完全一致，且 VPN 相关的访问器都回落到安全的默认值。
func TestVPNDisabledHasNoEffect(t *testing.T) {
	cfg, err := ParseConfigJSON(`{
		"version": 3,
		"servers": [{"address": "a.example.com", "port": 443, "password": "p", "default": true}]
	}`)
	if err != nil {
		t.Fatalf("ParseConfigJSON: %v", err)
	}
	if cfg.VPN.Enabled {
		t.Error("VPN.Enabled = true for a config without a vpn key")
	}
	if cfg.VPNPeerPort() != sharedconfig.DefaultVPNPeerPort {
		t.Errorf("VPNPeerPort() = %d, want %d", cfg.VPNPeerPort(), sharedconfig.DefaultVPNPeerPort)
	}
	if cfg.VPNDERPAddr() != "a.example.com:443" {
		t.Errorf("VPNDERPAddr() = %q, want a.example.com:443", cfg.VPNDERPAddr())
	}
	if !cfg.VPN.RelayOnlyEnabled() {
		t.Error("RelayOnlyEnabled() = false, want the default true")
	}
}
