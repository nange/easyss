package config

import "testing"

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
func TestParseVPNOverlayCIDR(t *testing.T) {
	t.Run("空值取默认段", func(t *testing.T) {
		got, err := ParseVPNOverlayCIDR("")
		if err != nil {
			t.Fatalf("ParseVPNOverlayCIDR(\"\") error: %v", err)
		}
		if want := DefaultVPNOverlayPrefix(); got != want {
			t.Errorf("ParseVPNOverlayCIDR(\"\") = %v, want %v", got, want)
		}
	})

	t.Run("合法值归一化为网络地址", func(t *testing.T) {
		got, err := ParseVPNOverlayCIDR("198.19.0.5/24")
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
		} {
			if _, err := ParseVPNOverlayCIDR(in); err == nil {
				t.Errorf("ParseVPNOverlayCIDR(%q) = nil error, want error", in)
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
	cgnat, err := ParseVPNOverlayCIDR("100.64.0.0/10")
	if err != nil {
		t.Fatalf("unexpected error parsing the CGNAT range: %v", err)
	}
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
