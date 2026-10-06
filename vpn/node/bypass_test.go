package vpnnode

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

// lookupTable 造一个可注入的解析函数与调用计数：解析结果按主机名给出，未列出的
// 主机报错。真实解析需要网络，而本文件的契约只关心"谁进了并集、谁被查了几次"。
func lookupTable(t *testing.T, table map[string][]string) (func(context.Context, string) ([]netip.Addr, error), *int) {
	t.Helper()

	calls := 0
	fn := func(_ context.Context, host string) ([]netip.Addr, error) {
		calls++
		raw, ok := table[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		addrs := make([]netip.Addr, 0, len(raw))
		for _, s := range raw {
			addrs = append(addrs, netip.MustParseAddr(s))
		}
		return addrs, nil
	}
	return fn, &calls
}

func addrs(t *testing.T, want ...string) []netip.Addr {
	t.Helper()

	out := make([]netip.Addr, 0, len(want))
	for _, s := range want {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// TestBypassUnionsLocalServerAndPeerDERPHosts 固定并集的来源，这是 8.2 的核心：
// 本地标记的 S 是本节点对端面接入中继的出口，而每个对端地址内嵌的 DERP 主机是
// 访问该对端的出口——跨 S 部署时两者不同，缺一个就会让那条连接被 TUN 捕获。
func TestBypassUnionsLocalServerAndPeerDERPHosts(t *testing.T) {
	lookup, calls := lookupTable(t, map[string][]string{
		"peer-a.derp.example": {"203.0.113.7"},
		"peer-b.derp.example": {"198.51.100.9"},
	})
	b := NewBypass(BypassOptions{
		LocalDERPAddr: "local.derp.example:443",
		Peers: []PeerRef{
			{HostName: "a", Address: fullAddr(t, "peer-a.derp.example:443")},
			{HostName: "b", Address: fullAddr(t, "peer-b.derp.example:8443")},
		},
	})
	b.lookup = lookup

	got := b.IPs(context.Background(), []string{"192.0.2.10"})
	want := addrs(t, "192.0.2.10", "198.51.100.9", "203.0.113.7")
	if !slices.Equal(got, want) {
		t.Fatalf("IPs = %v, want the sorted union %v", got, want)
	}
	// 本地 S 已经由服务端域名预解析给出，端口也来自 peers，因此只该查两次对端。
	if *calls != 2 {
		t.Errorf("resolver calls = %d, want 2 (the pre-resolved local server address must not be looked up)", *calls)
	}
}

// TestBypassResolvesLocalDERPHostWithoutPreResolvedIPs 固定回退路径：没有预解析
// 结果时（服务端地址是字面 IP、或 DNS 缓存尚不可用），本地 S 的主机名由本包解析。
func TestBypassResolvesLocalDERPHostWithoutPreResolvedIPs(t *testing.T) {
	lookup, calls := lookupTable(t, map[string][]string{
		"local.derp.example": {"192.0.2.10"},
	})
	b := NewBypass(BypassOptions{LocalDERPAddr: "local.derp.example:443"})
	b.lookup = lookup

	got := b.IPs(context.Background(), nil)
	if want := addrs(t, "192.0.2.10"); !slices.Equal(got, want) {
		t.Fatalf("IPs = %v, want %v", got, want)
	}
	if *calls != 1 {
		t.Errorf("resolver calls = %d, want 1", *calls)
	}
}

// TestBypassLiteralAddressesNeedNoLookup 验证字面 IP 不触发解析：DERP 主机也可能
// 就是服务端的字面 IP，这种部署不该因为 DNS 不可用而失去绕行路由。
func TestBypassLiteralAddressesNeedNoLookup(t *testing.T) {
	lookup, calls := lookupTable(t, nil) // 任何主机都解析失败
	b := NewBypass(BypassOptions{LocalDERPAddr: "203.0.113.5:443"})
	b.lookup = lookup

	got := b.IPs(context.Background(), nil)
	if want := addrs(t, "203.0.113.5"); !slices.Equal(got, want) {
		t.Fatalf("IPs = %v, want %v", got, want)
	}
	if *calls != 0 {
		t.Errorf("resolver calls = %d, want 0 for a literal address", *calls)
	}
}

// TestBypassCachesResolution 固定缓存与去重：同一个 DERP 主机（例如所有节点都标记
// 同一个 S）只解析一次，重复计算不再产生查询——启用 TUN 会被反复触发。
func TestBypassCachesResolution(t *testing.T) {
	lookup, calls := lookupTable(t, map[string][]string{
		"shared.derp.example": {"203.0.113.7"},
	})
	b := NewBypass(BypassOptions{
		LocalDERPAddr: "shared.derp.example:443",
		Peers: []PeerRef{
			{HostName: "a", Address: fullAddr(t, "shared.derp.example:443")},
			{HostName: "b", Address: fullAddr(t, "shared.derp.example:443")},
		},
	})
	b.lookup = lookup

	want := addrs(t, "203.0.113.7")
	for i := range 2 {
		if got := b.IPs(context.Background(), nil); !slices.Equal(got, want) {
			t.Fatalf("call %d: IPs = %v, want the deduplicated %v", i, got, want)
		}
	}
	if *calls != 1 {
		t.Errorf("resolver calls = %d, want 1 (the host is cached and shared by the local S and both peers)", *calls)
	}
}

// TestBypassKeepsTheHostsItCanResolve 固定失败的作用域：一个主机解析不出来只影响
// 它自己，其余主机的绕行路由照常安装。整条链一起失败会把"某个对端的 DERP 暂时
// 解析不了"升级成"TUN 完全不可用"。
func TestBypassKeepsTheHostsItCanResolve(t *testing.T) {
	lookup, _ := lookupTable(t, map[string][]string{
		"peer-b.derp.example": {"198.51.100.9"},
	})
	b := NewBypass(BypassOptions{
		LocalDERPAddr: "unresolvable.example:443",
		Peers: []PeerRef{
			{HostName: "a", Address: fullAddr(t, "peer-a.derp.example:443")},
			{HostName: "b", Address: fullAddr(t, "peer-b.derp.example:443")},
		},
	})
	b.lookup = lookup

	got := b.IPs(context.Background(), nil)
	if want := addrs(t, "198.51.100.9"); !slices.Equal(got, want) {
		t.Fatalf("IPs = %v, want only the resolvable host %v", got, want)
	}
}

// TestBypassDropsIPv6 固定本期只绕行 IPv4：创建脚本按 /32 主机路由安装（8.2），
// 一个只有 AAAA 记录的主机无法被绕行——这里断言它被丢弃而不是产出一条错误的命令。
func TestBypassDropsIPv6(t *testing.T) {
	lookup, _ := lookupTable(t, map[string][]string{
		"v6-only.example": {"2001:db8::1"},
	})
	b := NewBypass(BypassOptions{
		LocalDERPAddr: "v6-only.example:443",
		Peers: []PeerRef{
			{HostName: "a", Address: fullAddr(t, "[2001:db8::9]:443")},
		},
	})
	b.lookup = lookup

	if got := b.IPs(context.Background(), nil); len(got) != 0 {
		t.Fatalf("IPs = %v, want nil: only IPv4 addresses can be bypassed", got)
	}
}

// TestNewBypassSkipsUnparsablePeers 验证构造期对坏地址的容错：NewConfig 会拒收它们，
// 而这里必须只跳过该对端而不是 panic 或让整份配置不可用。
func TestNewBypassSkipsUnparsablePeers(t *testing.T) {
	b := NewBypass(BypassOptions{
		LocalDERPAddr: "203.0.113.5:443",
		Peers: []PeerRef{
			{HostName: "broken", Address: "not-a-tailcat-address"},
			{HostName: "ok", Address: fullAddr(t, "peer.derp.example:443")},
		},
	})
	lookup, _ := lookupTable(t, map[string][]string{
		"peer.derp.example": {"198.51.100.9"},
	})
	b.lookup = lookup

	got := b.IPs(context.Background(), nil)
	if want := addrs(t, "198.51.100.9", "203.0.113.5"); !slices.Equal(got, want) {
		t.Fatalf("IPs = %v, want %v", got, want)
	}
}

// TestBypassNilIsSafe 验证未启用 VPN 的会话（nil 计算器）上是空操作。
func TestBypassNilIsSafe(t *testing.T) {
	var b *Bypass
	if got := b.IPs(context.Background(), []string{"192.0.2.10"}); got != nil {
		t.Fatalf("IPs on a nil Bypass = %v, want nil", got)
	}
}
