package config

import (
	"encoding/json"
	"net/netip"
	"testing"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// TestDERPServerFallback 固定"谁提供内嵌 DERP"的选择规则：第一条被 derp 标记
// 的条目优先；没有任何条目标记时回退 servers[0]，**不跟随 default 标记**。
//
// 不跟随 default 是刻意的：DERP 中继是谁，与"代理走哪条 server"是两个独立的
// 选择，若跟着 default 走，用户切换默认 server 会静默改掉本节点对外通告的地址，
// 而每个对端都得跟着改配置。
func TestDERPServerFallback(t *testing.T) {
	t.Run("被标记的条目优先", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, Default: true},
			{Address: "b.example.com", Port: 443, DERP: true},
		}}
		if got := cfg.DERPServer(); got == nil || got.Address != "b.example.com" {
			t.Fatalf("DERPServer() = %v, want b.example.com", got)
		}
	})

	t.Run("无标记时回退 servers[0] 而不是 default 标记", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443},
			{Address: "b.example.com", Port: 443, Default: true},
		}}
		if got := cfg.DERPServer(); got == nil || got.Address != "a.example.com" {
			t.Fatalf("DERPServer() = %v, want a.example.com (servers[0])", got)
		}
	})

	t.Run("有标记时忽略 default 标记", func(t *testing.T) {
		cfg := &ClientConfig{Servers: []*ServerProfile{
			{Address: "a.example.com", Port: 443, Default: true},
			{Address: "b.example.com", Port: 443, DERP: true},
			{Address: "c.example.com", Port: 443, DERP: true},
		}}
		if got := cfg.DERPServer(); got == nil || got.Address != "b.example.com" {
			t.Fatalf("DERPServer() = %v, want the first derp-marked entry b.example.com", got)
		}
	})

	t.Run("没有服务端条目", func(t *testing.T) {
		if got := (&ClientConfig{}).DERPServer(); got != nil {
			t.Fatalf("DERPServer() = %v, want nil", got)
		}
	})
}

// TestVPNDERPAddr 固定 vpn.derp_addr 的默认来源与覆盖：显式值优先，否则从
// DERPServer() 派生；派生值必须是 host:port 形态（IPv6 字面量带方括号），
// 因为对端要把它当作 region 的 HostName/DERPPort 使用。
func TestVPNDERPAddr(t *testing.T) {
	t.Run("未配置时从被标记的 server 派生", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Address: "a.example.com", Port: 8443, Default: true},
				{Address: "relay.example.com", Port: 9443, DERP: true},
			},
		}
		if got, want := cfg.VPNDERPAddr(), "relay.example.com:9443"; got != want {
			t.Errorf("VPNDERPAddr() = %q, want %q", got, want)
		}
	})

	t.Run("未配置且无标记时取 servers[0]", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{
				{Address: "a.example.com", Port: 443},
				{Address: "b.example.com", Port: 443, Default: true},
			},
		}
		if got, want := cfg.VPNDERPAddr(), "a.example.com:443"; got != want {
			t.Errorf("VPNDERPAddr() = %q, want %q", got, want)
		}
	})

	t.Run("显式配置覆盖派生", func(t *testing.T) {
		cfg := &ClientConfig{
			Servers: []*ServerProfile{{Address: "a.example.com", Port: 443}},
			VPN:     VPNConfig{DERPAddr: "relay.internal:8443"},
		}
		if got, want := cfg.VPNDERPAddr(), "relay.internal:8443"; got != want {
			t.Errorf("VPNDERPAddr() = %q, want %q", got, want)
		}
	})

	t.Run("没有服务端条目且未显式配置时为空", func(t *testing.T) {
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
// README/设计文档一致），并守住 servers[].derp 的解析。
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
