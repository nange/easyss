package vpnnode

import (
	"strings"
	"testing"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/types/key"

	sharedconfig "github.com/nange/easyss/v3/config"

	vpn "github.com/nange/easyss/v3/vpn"
)

// validOptions 返回一份最小的合法输入：一个对端、显式的 DERP 地址与 peer 端口。
func validOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		RelayOnly:   true,
		PeerPort:    sharedconfig.DefaultVPNPeerPort,
		OverlayCIDR: sharedconfig.DefaultVPNOverlayCIDR,
		DERPAddr:    "relay.example.com:8443",
		Peers: []PeerRef{{
			HostName: "b",
			Address:  fullAddr(t, "relay.example.com:8443"),
		}},
	}
}

// TestNewConfigHappyPath 固定运行期视图的构造：默认值被补齐、字段原样传递。
func TestNewConfigHappyPath(t *testing.T) {
	opts := validOptions(t)
	cfg, err := NewConfig(opts)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if !cfg.RelayOnly {
		t.Error("RelayOnly = false, want true")
	}
	if cfg.PeerPort != sharedconfig.DefaultVPNPeerPort {
		t.Errorf("PeerPort = %d, want %d", cfg.PeerPort, sharedconfig.DefaultVPNPeerPort)
	}
	if want := sharedconfig.DefaultVPNOverlayPrefix(); cfg.Overlay != want {
		t.Errorf("Overlay = %v, want %v", cfg.Overlay, want)
	}
	if cfg.DERPAddr != "relay.example.com:8443" {
		t.Errorf("DERPAddr = %q, want relay.example.com:8443", cfg.DERPAddr)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].HostName != "b" {
		t.Fatalf("Peers = %+v, want one peer named b", cfg.Peers)
	}
	if cfg.Peers[0].Port != sharedconfig.DefaultVPNPeerPort {
		t.Errorf("peer port = %d, want the default %d", cfg.Peers[0].Port, sharedconfig.DefaultVPNPeerPort)
	}
	if cfg.AllowClients != nil {
		t.Errorf("AllowClients = %v, want nil for an empty list", cfg.AllowClients)
	}
}

// TestNewConfigRejectsShortPeerAddr 是 4.7 契约的守门测试：短格式（只带 region
// ID）的对端地址必须在启动阶段被拒，而不是等第一次访问对端时才去拉官方的
// DERPMap。这也是"零控制面 / 零 Tailscale 官方依赖"能否成立的关键。
func TestNewConfigRejectsShortPeerAddr(t *testing.T) {
	opts := validOptions(t)
	opts.Peers[0].Address = string(newConnInfo(nil, vpn.RegionID, true).Addr())

	_, err := NewConfig(opts)
	if err == nil {
		t.Fatal("NewConfig accepted a short-format peer address, want error")
	}
	if !strings.Contains(err.Error(), "not fully expanded") {
		t.Errorf("error %q should explain that the address is not fully expanded", err)
	}
	if !strings.Contains(err.Error(), tailcat.DefaultDERPMapURL) {
		t.Errorf("error %q should point at the official DERPMap", err)
	}
	if !strings.Contains(err.Error(), "vpn.peers[0]") {
		t.Errorf("error %q should identify the offending peer", err)
	}
}

// TestNewConfigPeerValidation 固定 host_name 的校验：它会被当作 DNS 名字使用，
// 因此必须唯一、不能是 IP 字面量、也不能含空白/冒号/斜杠这类会破坏 host 解析的
// 字符——否则这个对端在运行期永远匹配不上，却没有任何提示。
func TestNewConfigPeerValidation(t *testing.T) {
	cases := []struct {
		name  string
		peers []PeerRef
		want  string
	}{
		{
			name:  "缺少 host_name",
			peers: []PeerRef{{Address: "x"}},
			want:  "host_name is required",
		},
		{
			name:  "host_name 是 IP 字面量",
			peers: []PeerRef{{HostName: "198.19.0.1", Address: "x"}},
			want:  "IP literal",
		},
		{
			name:  "host_name 含端口分隔符",
			peers: []PeerRef{{HostName: "b:8080", Address: "x"}},
			want:  "invalid character",
		},
		{
			name:  "host_name 含空白",
			peers: []PeerRef{{HostName: "b c", Address: "x"}},
			want:  "invalid character",
		},
		{
			name:  "缺少 address",
			peers: []PeerRef{{HostName: "b"}},
			want:  "tailcat address is empty",
		},
		{
			name:  "address 不是 tailcat 地址",
			peers: []PeerRef{{HostName: "b", Address: "https://example.com"}},
			want:  "invalid tailcat address",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := validOptions(t)
			opts.Peers = tc.peers
			_, err := NewConfig(opts)
			if err == nil {
				t.Fatalf("NewConfig accepted %+v, want error containing %q", tc.peers, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err, tc.want)
			}
		})
	}
}

// TestNewConfigRejectsDuplicateHostName 固定 host_name 的唯一性：忽略大小写，
// 因为 DNS 名字本身不区分大小写，两个只差大小写的名字在运行期无法区分。
func TestNewConfigRejectsDuplicateHostName(t *testing.T) {
	opts := validOptions(t)
	addr := opts.Peers[0].Address
	opts.Peers = []PeerRef{
		{HostName: "b", Address: addr},
		{HostName: "B", Address: addr},
	}
	_, err := NewConfig(opts)
	if err == nil {
		t.Fatal("NewConfig accepted duplicate host names, want error")
	}
	if !strings.Contains(err.Error(), "duplicates") {
		t.Errorf("error %q should mention the duplicate", err)
	}
}

// TestNewConfigPeerPortDefaults 固定对端端口的默认值语义与本地 peer_port 一致：
// 未配置（0）或越界都取默认端口。
func TestNewConfigPeerPortDefaults(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want int
	}{
		{0, sharedconfig.DefaultVPNPeerPort},
		{-1, sharedconfig.DefaultVPNPeerPort},
		{6081, 6081},
		{70000, sharedconfig.DefaultVPNPeerPort},
	} {
		opts := validOptions(t)
		opts.Peers[0].Port = tc.in
		cfg, err := NewConfig(opts)
		if err != nil {
			t.Fatalf("NewConfig(peer port %d): %v", tc.in, err)
		}
		if cfg.Peers[0].Port != tc.want {
			t.Errorf("peer port %d -> %d, want %d", tc.in, cfg.Peers[0].Port, tc.want)
		}
	}
}

// TestNewConfigRejectsBadLocalValues 固定本地值（peer_port / overlay_cidr /
// derp_addr）的校验都会在启动阶段报错。
func TestNewConfigRejectsBadLocalValues(t *testing.T) {
	t.Run("peer_port 越界", func(t *testing.T) {
		for _, port := range []int{0, -1, 65536} {
			opts := validOptions(t)
			opts.PeerPort = port
			if _, err := NewConfig(opts); err == nil {
				t.Errorf("NewConfig(peer_port %d) = nil, want error", port)
			}
		}
	})

	t.Run("overlay_cidr 非法", func(t *testing.T) {
		for _, cidr := range []string{"not-a-cidr", "fd7a:115c:a1e0::/48", "198.19.0.0/31"} {
			opts := validOptions(t)
			opts.OverlayCIDR = cidr
			_, err := NewConfig(opts)
			if err == nil {
				t.Errorf("NewConfig(overlay_cidr %q) = nil, want error", cidr)
			}
			if err != nil && !strings.Contains(err.Error(), "overlay_cidr") {
				t.Errorf("error %q should identify vpn.overlay_cidr", err)
			}
		}
	})

	t.Run("overlay_cidr 留空取默认段", func(t *testing.T) {
		opts := validOptions(t)
		opts.OverlayCIDR = ""
		cfg, err := NewConfig(opts)
		if err != nil {
			t.Fatalf("NewConfig: %v", err)
		}
		if want := sharedconfig.DefaultVPNOverlayPrefix(); cfg.Overlay != want {
			t.Errorf("Overlay = %v, want %v", cfg.Overlay, want)
		}
	})

	t.Run("derp_addr 非法", func(t *testing.T) {
		for _, addr := range []string{"", "relay.example.com", ":8443", "relay.example.com:https"} {
			opts := validOptions(t)
			opts.DERPAddr = addr
			_, err := NewConfig(opts)
			if err == nil {
				t.Errorf("NewConfig(derp_addr %q) = nil, want error", addr)
			}
			if err != nil && !strings.Contains(err.Error(), "derp_addr") {
				t.Errorf("error %q should identify vpn.derp_addr", err)
			}
		}
	})
}

// TestNewConfigAllowClients 固定 allow_clients 的解析：按 nodekey 文本格式
// （即 key.NodePublic.String() 的形态）解析并去重，非法值在启动阶段报错。
func TestNewConfigAllowClients(t *testing.T) {
	k1 := key.NewNode().Public()
	k2 := key.NewNode().Public()

	t.Run("合法值被解析并去重", func(t *testing.T) {
		opts := validOptions(t)
		opts.AllowClients = []string{k1.String(), k2.String(), k1.String()}
		cfg, err := NewConfig(opts)
		if err != nil {
			t.Fatalf("NewConfig: %v", err)
		}
		if len(cfg.AllowClients) != 2 {
			t.Fatalf("AllowClients = %v, want 2 unique keys", cfg.AllowClients)
		}
		if cfg.AllowClients[0] != k1 || cfg.AllowClients[1] != k2 {
			t.Errorf("AllowClients = %v, want [%v %v]", cfg.AllowClients, k1, k2)
		}
	})

	t.Run("非法值报错", func(t *testing.T) {
		for _, s := range []string{"", "not-a-key", "abc", "nodekey:zz"} {
			opts := validOptions(t)
			opts.AllowClients = []string{s}
			_, err := NewConfig(opts)
			if err == nil {
				t.Errorf("NewConfig(allow_clients %q) = nil, want error", s)
			}
			if err != nil && !strings.Contains(err.Error(), "allow_clients") {
				t.Errorf("error %q should identify vpn.allow_clients", err)
			}
		}
	})
}

// TestNewConfigAllowsNoPeers 固定"只做被访问方"的节点是合法配置：它没有任何要
// 访问的对端，但仍然跑对端面供别人访问。
func TestNewConfigAllowsNoPeers(t *testing.T) {
	opts := validOptions(t)
	opts.Peers = nil
	cfg, err := NewConfig(opts)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if len(cfg.Peers) != 0 {
		t.Errorf("Peers = %v, want empty", cfg.Peers)
	}
}
