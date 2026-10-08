package config

import (
	"encoding/json"
	"net/netip"
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

// TestVPNDERPAddrs 固定通告列表的派生：显式 vpn.derp_addr 退化成单节点，否则由
// 全部 derp 标记条目派生；返回值必须是 host:port（IPv6 带方括号）、规范化去重且
// 保持配置顺序（对端会按这个顺序尝试中继节点）。
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

	t.Run("显式配置覆盖整组节点", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Address: "a.example.com", Port: 443, DERP: true},
				{Address: "b.example.com", Port: 443, DERP: true},
			},
			VPN: VPNConfig{DERPAddr: "relay.internal:8443"},
		}
		got := cfg.VPNDERPAddrs()
		if !slices.Equal(got, []string{"relay.internal:8443"}) {
			t.Errorf("VPNDERPAddrs() = %v, want exactly the explicit override", got)
		}
	})

	t.Run("没有服务端条目且未显式配置时为空", func(t *testing.T) {
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

// TestValidateDERPServer 固定"当前服务端必须是声明的中继之一"这条不变量：内嵌
// DERP 只接待经本服务端隧道送达的连接，声明列表里没有它时中继永远连不上，因此
// VPN 必须在启动阶段拒绝（见 runner.vpnOptions）而不是让用户看到"连不上"。
func TestValidateDERPServer(t *testing.T) {
	t.Run("当前服务端在列表里", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, DERP: true},
			{Address: "b.example.com", Port: 443, DERP: true, Default: true},
		}}
		if err := cfg.ValidateDERPServer(); err != nil {
			t.Errorf("ValidateDERPServer() = %v, want nil", err)
		}
	})

	t.Run("大小写不同不算不匹配", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "RELAY.example.com", Port: 443, DERP: true},
			{Address: "relay.example.com", Port: 443, Default: true},
		}}
		if err := cfg.ValidateDERPServer(); err != nil {
			t.Errorf("ValidateDERPServer() = %v, want nil: the two entries are the same relay", err)
		}
	})

	t.Run("当前服务端不在列表里时报错并点名双方", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, DERP: true},
			{Address: "b.example.com", Port: 443, DERP: true},
			{Address: "c.example.com", Port: 443, Default: true},
		}}
		err := cfg.ValidateDERPServer()
		if err == nil {
			t.Fatal("ValidateDERPServer() = nil, want an error for an unmarked current server")
		}
		for _, want := range []string{"c.example.com:443", "a.example.com:443", "b.example.com:443", "derp"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should mention %q", err, want)
			}
		}
	})

	t.Run("无标记时当前服务端就是列表本身", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443},
			{Address: "b.example.com", Port: 443, Default: true},
		}}
		if err := cfg.ValidateDERPServer(); err != nil {
			t.Errorf("ValidateDERPServer() = %v, want nil", err)
		}
	})

	t.Run("显式 derp_addr 与当前服务端不同时报错", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{{Address: "a.example.com", Port: 443, Default: true}},
			VPN:     VPNConfig{DERPAddr: "relay.internal:8443"},
		}
		if err := cfg.ValidateDERPServer(); err == nil {
			t.Error("ValidateDERPServer() = nil, want an error: the explicit relay is not the current server")
		}
	})

	t.Run("没有可用列表时不在这里报错", func(t *testing.T) {
		if err := (&ClientConfig{}).ValidateDERPServer(); err != nil {
			t.Errorf("ValidateDERPServer() = %v, want nil (the VPN start path reports the empty list)", err)
		}
	})

	t.Run("列表里的地址都非法时不在这里报错", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{{Address: "a.example.com", Port: 443, Default: true}},
			VPN:     VPNConfig{DERPAddr: "not-a-host-port"},
		}
		// 这条配置真正的问题是"derp_addr 非法"，由 vpnnode.NewConfig 带节点序号报出；
		// 说成"当前服务端不在列表里"会把人引向错误的修法。
		if err := cfg.ValidateDERPServer(); err != nil {
			t.Errorf("ValidateDERPServer() = %v, want nil for an unparsable relay list", err)
		}
	})
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

// TestVPNOverlayPrefixFallback 固定访问器的容错行为：配置非法时回退默认段
// （并在日志里警告），严格报错由 vpn.NewConfig 负责。
func TestVPNOverlayPrefixFallback(t *testing.T) {
	cfg := &ClientConfig{VPN: VPNConfig{OverlayCIDR: "not-a-cidr"}}
	if got, want := cfg.VPNOverlayPrefix(), sharedconfig.DefaultVPNOverlayPrefix(); got != want {
		t.Errorf("VPNOverlayPrefix() = %v, want the default %v", got, want)
	}

	cfg.VPN.OverlayCIDR = "10.9.0.0/24"
	want := netip.MustParsePrefix("10.9.0.0/24")
	if got := cfg.VPNOverlayPrefix(); got != want {
		t.Errorf("VPNOverlayPrefix() = %v, want %v", got, want)
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
			"overlay_cidr": "10.9.0.0/24",
			"derp_addr": "relay.example.com:8443",
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
	if got, want := cfg.VPNOverlayPrefix(), sharedconfig.DefaultVPNOverlayPrefix(); got != want {
		t.Errorf("VPNOverlayPrefix() = %v, want %v", got, want)
	}
	if !cfg.VPN.RelayOnlyEnabled() {
		t.Error("RelayOnlyEnabled() = false, want the default true")
	}
}
