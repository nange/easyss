package config

import (
	"net/netip"
	"strings"
	"testing"
)

// TestNormalizeVPNPeerPort 固定 vpn.peer_port 归一化的唯一入口：非正值表示
// "未配置"（从 socks_port 派生），无法派生或派生结果越界时回退默认端口。
// 它与 http_port = socks_port + 1000 的既有惯例同源，因此偏移量的变化也必须
// 在这里被观察到。
func TestNormalizeVPNPeerPort(t *testing.T) {
	cases := []struct {
		name      string
		peerPort  int
		socksPort int
		want      int
	}{
		{"未配置且 socks_port 为默认值", 0, DefaultSocksPort, DefaultSocksPort + 2000},
		{"未配置且 socks_port 未设置", 0, 0, DefaultVPNPeerPort},
		{"未配置且 socks_port 为负", 0, -1, DefaultVPNPeerPort},
		{"显式配置原样保留", 7000, DefaultSocksPort, 7000},
		{"显式配置不受 socks_port 影响", 1234, 0, 1234},
		{"派生越界时回退默认值", 0, 64000, DefaultVPNPeerPort},
		{"派生恰好落在上界", 0, vpnMaxPort - vpnPeerPortOffset, vpnMaxPort},
		{"派生超过上界一格时回退", 0, vpnMaxPort - vpnPeerPortOffset + 1, DefaultVPNPeerPort},
		{"显式越界值回退默认值", vpnMaxPort + 1, DefaultSocksPort, DefaultVPNPeerPort},
		{"显式负值视为未配置", -1, DefaultSocksPort, DefaultSocksPort + 2000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeVPNPeerPort(tc.peerPort, tc.socksPort); got != tc.want {
				t.Errorf("NormalizeVPNPeerPort(%d, %d) = %d, want %d", tc.peerPort, tc.socksPort, got, tc.want)
			}
		})
	}
}

// TestNormalizeVPNPeerPortIsIdempotent 守护"已归一化的值再次归一化不变"。
// 派生结果会被写进节点对外通告的地址，两次归一化得到不同端口就意味着对端拿到的
// 端口与本机监听的不一致。
func TestNormalizeVPNPeerPortIsIdempotent(t *testing.T) {
	for _, socks := range []int{0, -1, 1, DefaultSocksPort, vpnMaxPort - vpnPeerPortOffset, vpnMaxPort} {
		once := NormalizeVPNPeerPort(0, socks)
		if twice := NormalizeVPNPeerPort(once, socks); twice != once {
			t.Errorf("NormalizeVPNPeerPort(NormalizeVPNPeerPort(0, %d), %d) = %d, want %d", socks, socks, twice, once)
		}
	}
}

// TestParseVPNOverlayCIDR 固定 overlay 段的校验与归一化：空值取默认段，非法值
// 必须报错（而不是静默回退），合法值归一化为网络地址。
//
// 入参只剩 DefaultVPNOverlayCIDR 一个来源，所以这一层现在守的是"常量被改坏"：
// 区间边界（/16 与 /30）只有在这里被固定下来，改坏常量才不会一路走到运行期才炸。
func TestParseVPNOverlayCIDR(t *testing.T) {
	t.Run("空值取默认段", func(t *testing.T) {
		got, err := parseVPNOverlayCIDR("")
		if err != nil {
			t.Fatalf("parseVPNOverlayCIDR(\"\") error: %v", err)
		}
		if want := DefaultVPNOverlayPrefix(); got != want {
			t.Errorf("parseVPNOverlayCIDR(\"\") = %v, want %v", got, want)
		}
	})

	t.Run("合法值归一化为网络地址", func(t *testing.T) {
		got, err := parseVPNOverlayCIDR("198.19.0.5/24")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := "198.19.0.0/24"; got.String() != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("非法值一律报错", func(t *testing.T) {
		for _, in := range []string{
			"198.19.0.0",          // 缺少前缀长度
			"not-a-cidr",          // 完全不是 CIDR
			"fd7a:115c:a1e0::/48", // 只支持 IPv4
			"198.19.0.0/31",       // 段太小，放不下对端
			"198.19.0.0/32",       // 同上
			"198.19.0.0/8",        // 段太大，槽位表会申请 MiB~GiB 级内存
		} {
			if _, err := parseVPNOverlayCIDR(in); err == nil {
				t.Errorf("parseVPNOverlayCIDR(%q) = nil error, want error", in)
			}
		}
	})
}

// TestDefaultVPNOverlayIsUsable 约束默认 overlay 段本身合法，并且不与 CGNAT
// (100.64.0.0/10) 重叠：CGNAT 段在物理接口上常有 on-link 路由，比 TUN 的
// 128.0.0.0/1 阶梯更具体，会把 overlay 流量压回物理网卡。
func TestDefaultVPNOverlayIsUsable(t *testing.T) {
	prefix := DefaultVPNOverlayPrefix()
	if !prefix.Addr().Is4() {
		t.Fatalf("DefaultVPNOverlayCIDR %q is not IPv4", DefaultVPNOverlayCIDR)
	}
	// CGNAT 段（/10）比 overlay 允许的最大段（/16）还大，因此它本身就是被拒收
	// 的段：这里按"拒绝"而不是"可解析"来断言，重叠检查用与它同址的更小段。
	if _, err := parseVPNOverlayCIDR("100.64.0.0/10"); err == nil {
		t.Errorf("a /10 overlay must be rejected: the slot table would be %d entries", 1<<(32-10))
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	if prefix.Overlaps(cgnat) {
		t.Errorf("DefaultVPNOverlayCIDR %q overlaps the CGNAT range %v", DefaultVPNOverlayCIDR, cgnat)
	}
}

// TestVPNPortsAreConsistent 约束默认值落在合法区间内，且默认 peer_port 与默认
// socks_port 的派生结果一致：否则"未配置"与"默认值"不再等价。
func TestVPNPortsAreConsistent(t *testing.T) {
	if DefaultVPNPeerPort <= 0 || DefaultVPNPeerPort > vpnMaxPort {
		t.Fatalf("DefaultVPNPeerPort = %d, want within 1..%d", DefaultVPNPeerPort, vpnMaxPort)
	}
	if got := NormalizeVPNPeerPort(0, DefaultSocksPort); got != DefaultVPNPeerPort {
		t.Errorf("deriving from the default socks_port yields %d, want DefaultVPNPeerPort %d", got, DefaultVPNPeerPort)
	}
}

// TestCanonicalDERPAddr 固定"同一个中继的不同书写必须等价"这条比较语义：多节点
// 的一致性校验（当前服务端是否在列表里、对端通告的节点集合是否相同）都建立在它
// 之上，任何一处漏掉规范化都会变成"配置明明一致却启动失败"。
func TestCanonicalDERPAddr(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"大小写与补零端口归一", "Relay.Example.com:0443", "relay.example.com:443"},
		{"已规范的值不变", "relay.example.com:443", "relay.example.com:443"},
		{"IPv4 字面量", "192.0.2.10:8443", "192.0.2.10:8443"},
		{"IPv6 字面量补方括号", "[2001:db8::1]:443", "[2001:db8::1]:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalDERPAddr(tc.in)
			if err != nil {
				t.Fatalf("CanonicalDERPAddr(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("CanonicalDERPAddr(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	t.Run("非法值报错", func(t *testing.T) {
		for _, in := range []string{"", "relay.example.com", ":443", "relay.example.com:", "relay.example.com:https", "relay.example.com:0", "relay.example.com:70000"} {
			if _, err := CanonicalDERPAddr(in); err == nil {
				t.Errorf("CanonicalDERPAddr(%q) = nil error, want error", in)
			}
		}
	})
}

// TestParseVPNMeshKey 固定 mesh_key 的两种书写：64 位 hex 原样（统一小写），其余
// 非空字符串按 SHA-256 派生。派生必须确定性——同一组服务端各自派生出的密钥只要
// 有一位不同，mesh 就会静默地建立不起来（对端只被当成普通 DERP 客户端）。
func TestParseVPNMeshKey(t *testing.T) {
	t.Run("64 位 hex 原样使用并统一小写", func(t *testing.T) {
		const in = "0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef"
		got, err := ParseVPNMeshKey(in)
		if err != nil {
			t.Fatalf("ParseVPNMeshKey: %v", err)
		}
		if want := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; got != want {
			t.Errorf("ParseVPNMeshKey(hex) = %q, want %q", got, want)
		}
	})

	t.Run("口令派生为 64 位 hex 且确定", func(t *testing.T) {
		first, err := ParseVPNMeshKey("mesh-passphrase")
		if err != nil {
			t.Fatalf("ParseVPNMeshKey: %v", err)
		}
		if len(first) != 64 {
			t.Fatalf("derived key %q is not 64 hex digits", first)
		}
		second, err := ParseVPNMeshKey("  mesh-passphrase  ")
		if err != nil {
			t.Fatalf("ParseVPNMeshKey (padded): %v", err)
		}
		if first != second {
			t.Errorf("the same passphrase derived %q and %q; whitespace must not change the key", first, second)
		}
		other, err := ParseVPNMeshKey("mesh-passphrase2")
		if err != nil {
			t.Fatalf("ParseVPNMeshKey: %v", err)
		}
		if first == other {
			t.Error("different passphrases derived the same key")
		}
	})

	t.Run("长度是 64 但不是 hex 时按口令派生", func(t *testing.T) {
		in := strings.Repeat("z", 64)
		got, err := ParseVPNMeshKey(in)
		if err != nil {
			t.Fatalf("ParseVPNMeshKey: %v", err)
		}
		if got == in {
			t.Error("a 64-character non-hex value must be hashed, not passed through")
		}
		if len(got) != 64 {
			t.Errorf("derived key %q is not 64 hex digits", got)
		}
	})

	t.Run("空值与空白报错", func(t *testing.T) {
		for _, in := range []string{"", "   ", "\t\n"} {
			if _, err := ParseVPNMeshKey(in); err == nil {
				t.Errorf("ParseVPNMeshKey(%q) = nil error, want error", in)
			}
		}
	})
}
