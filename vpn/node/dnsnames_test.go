package vpnnode

import (
	"strings"
	"testing"
)

// TestResolveStaticMatchesPeerNames 固定静态名解析的归一化规则：DNS 问题名带
// 根点、比较不区分大小写，返回的是该对端确定的 overlay IPv4。
func TestResolveStaticMatchesPeerNames(t *testing.T) {
	peers := overlayPeers(t, 2)
	route, overlay := newTestRoute(t, peers...)

	for _, p := range peers {
		want, ok := overlay.Addr(p.HostName)
		if !ok {
			t.Fatalf("overlay has no address for %s", p.HostName)
		}
		for _, name := range []string{
			p.HostName,
			p.HostName + ".",
			strings.ToUpper(p.HostName) + ".",
		} {
			got, ok := route.ResolveStatic(name)
			if !ok {
				t.Fatalf("ResolveStatic(%q) missed the peer %s", name, p.HostName)
			}
			if got != want {
				t.Errorf("ResolveStatic(%q) = %s, want %s", name, got, want)
			}
		}
	}
}

// TestResolveStaticRejectsNonPeers 验证钩子只在命中时改变行为：未知名字、空名与
// 一个看似相邻的 overlay 地址都不算对端名。
func TestResolveStaticRejectsNonPeers(t *testing.T) {
	peers := overlayPeers(t, 1)
	route, overlay := newTestRoute(t, peers...)

	addr, ok := overlay.Addr(peers[0].HostName)
	if !ok {
		t.Fatal("overlay has no address for the peer")
	}
	// 紧邻 overlay 地址的另一个地址：前缀相同，但不是分配出去的槽位。
	other := addr.Next()

	for _, name := range []string{"", ".", "elsewhere.", "example.com.", other.String(), other.String() + "."} {
		if got, ok := route.ResolveStatic(name); ok {
			t.Errorf("ResolveStatic(%q) = %s, true; want a miss", name, got)
		}
	}
}

// TestResolveStaticNilRouteIsSafe 验证一个未装配的 Route 不会 panic：钩子可能
// 在早于初始化的路径上被问到。
func TestResolveStaticNilRouteIsSafe(t *testing.T) {
	var route *Route
	if _, ok := route.ResolveStatic("b."); ok {
		t.Fatal("nil route resolved a name")
	}
	if _, ok := (&Route{}).ResolveStatic("b."); ok {
		t.Fatal("route without an overlay resolved a name")
	}
}
