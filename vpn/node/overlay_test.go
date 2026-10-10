package vpnnode

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	sharedconfig "github.com/nange/easyss/v3/config"

	"github.com/nange/easyss/v3/vpn"
)

// overlayPeers 造出 n 个彼此独立的对端：每个都有自己的真实公钥，且地址都是
// 完整展开格式（分配逻辑的唯一输入是公钥，用假地址会掩盖真实契约）。
func overlayPeers(t *testing.T, n int) []PeerRef {
	t.Helper()
	region, err := vpn.BuildRegion("relay.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	peers := make([]PeerRef, 0, n)
	for i := range n {
		ci := newConnInfo([]*tailcfg.DERPRegion{region}, 0, true)
		p := PeerRef{
			HostName: fmt.Sprintf("node-%02d", i),
			Address:  string(ci.Addr()),
			Port:     sharedconfig.DefaultVPNPeerPort,
		}
		if err := AssertFullAddr(p.Address); err != nil {
			t.Fatalf("overlayPeers produced a non self-contained address: %v", err)
		}
		peers = append(peers, p)
	}
	return peers
}

// TestAssignIsDeterministic 固定 overlay 分配的两条不变量：同一组对端得到同一组
// 地址（跨启动稳定），且结果与配置里的书写顺序无关。
func TestAssignIsDeterministic(t *testing.T) {
	prefix := netip.MustParsePrefix("198.19.0.0/24")
	peers := overlayPeers(t, 12)

	first, err := Assign(prefix, peers)
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	// 打乱顺序后重新分配，结果必须逐项一致。
	shuffled := make([]PeerRef, len(peers))
	copy(shuffled, peers)
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	second, err := Assign(prefix, shuffled)
	if err != nil {
		t.Fatalf("Assign(shuffled): %v", err)
	}

	for _, p := range peers {
		a, ok := first.Addr(p.HostName)
		if !ok {
			t.Fatalf("first overlay has no address for %s", p.HostName)
		}
		b, ok := second.Addr(p.HostName)
		if !ok {
			t.Fatalf("second overlay has no address for %s", p.HostName)
		}
		if a != b {
			t.Errorf("%s: %v vs %v after reordering (assignment must not depend on config order)", p.HostName, a, b)
		}
	}
}

// TestAssignGivesDistinctAddressesInRange 固定分配结果落在 overlay 段内、彼此不
// 冲突，并且不落在网络地址与广播地址上。
func TestAssignGivesDistinctAddressesInRange(t *testing.T) {
	prefix := netip.MustParsePrefix("198.19.0.0/24")
	peers := overlayPeers(t, 40)

	o, err := Assign(prefix, peers)
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}

	network := prefix.Masked().Addr()
	broadcast := broadcastAddr(prefix)
	seen := make(map[netip.Addr]string, len(peers))
	for _, p := range peers {
		addr, ok := o.Addr(p.HostName)
		if !ok {
			t.Fatalf("no address for %s", p.HostName)
		}
		if !prefix.Contains(addr) {
			t.Errorf("%s got %v, outside %v", p.HostName, addr, prefix)
		}
		if addr == network {
			t.Errorf("%s got the network address %v", p.HostName, addr)
		}
		if addr == broadcast {
			t.Errorf("%s got the broadcast address %v", p.HostName, addr)
		}
		if prev, dup := seen[addr]; dup {
			t.Errorf("%s and %s share the overlay address %v", prev, p.HostName, addr)
		}
		seen[addr] = p.HostName
	}
}

// broadcastAddr 返回 prefix 内的最后一个地址。
func broadcastAddr(p netip.Prefix) netip.Addr {
	a4 := p.Masked().Addr().As4()
	last := binary.BigEndian.Uint32(a4[:]) | (1<<(32-p.Bits()) - 1)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], last)
	return netip.AddrFrom4(b)
}

// TestAssignLookup 固定访问侧的两条查找路径：host_name（不区分大小写）与
// overlay 字面 IP，并固定两条路径都不会把未分配的名字/地址解析成对端。
func TestAssignLookup(t *testing.T) {
	prefix := netip.MustParsePrefix("198.19.0.0/24")
	peers := overlayPeers(t, 3)

	o, err := Assign(prefix, peers)
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	want := peers[1]
	addr, ok := o.Addr(want.HostName)
	if !ok {
		t.Fatalf("no address for %s", want.HostName)
	}

	for _, host := range []string{want.HostName, strings.ToUpper(want.HostName), addr.String()} {
		got, ok := o.Lookup(host)
		if !ok {
			t.Errorf("Lookup(%q) missed", host)
			continue
		}
		if got.HostName != want.HostName {
			t.Errorf("Lookup(%q) = %s, want %s", host, got.HostName, want.HostName)
		}
	}

	if _, ok := o.Lookup("unknown-node"); ok {
		t.Error("Lookup of an unknown name hit")
	}
	// 段内但未分配，以及段外地址都不该命中。段内那个地址必须由分配结果推导：
	// 槽位来自公钥哈希，任何写死的段内地址都可能恰好被本次分配占用（这正是
	// 这个测试曾经的偶发失败来源）。
	for _, host := range []string{overlayFreeAddr(t, o), "10.0.0.1", "not-an-ip"} {
		if _, ok := o.Lookup(host); ok {
			t.Errorf("Lookup(%q) hit, want miss", host)
		}
	}
}

// overlayFreeAddr 返回 o 的段内一个确定未被分配的宿主地址，用于固定"未分配的
// overlay 地址不该命中 Lookup"。遍历从网络地址之后开始，跳过广播地址。
//
// 段内为空（满段）时无从取未分配地址，直接判失败而不是返回零值——调用方都是
// 小规模分配，这种情况只可能来自 Assign 自身的缺陷。
func overlayFreeAddr(t *testing.T, o *Overlay) string {
	t.Helper()
	taken := make(map[netip.Addr]bool, len(o.Peers()))
	for _, p := range o.Peers() {
		if addr, ok := o.Addr(p.HostName); ok {
			taken[addr] = true
		}
	}

	prefix := o.Prefix()
	for addr := prefix.Masked().Addr().Next(); prefix.Contains(addr) && addr != broadcastAddr(prefix); addr = addr.Next() {
		if !taken[addr] {
			return addr.String()
		}
	}
	t.Fatalf("overlay %v has no free address to probe", prefix)
	return ""
}

// TestAssignRejectsDuplicateNode 固定"两个 host_name 指向同一个节点"是配置错误：
// 给它们两个 overlay 地址只会让用户以为那是两台机器。
func TestAssignRejectsDuplicateNode(t *testing.T) {
	prefix := netip.MustParsePrefix("198.19.0.0/24")
	peers := overlayPeers(t, 2)
	peers[1].Address = peers[0].Address

	_, err := Assign(prefix, peers)
	if err == nil {
		t.Fatal("Assign accepted two peers with the same tailcat public key, want error")
	}
	if !strings.Contains(err.Error(), "same node") {
		t.Errorf("error %q should say the two peers point at the same node", err)
	}
}

// TestAssignCapacity 固定段太小时给出明确错误，而不是无限探测或 panic。
func TestAssignCapacity(t *testing.T) {
	// /30 只有两个可用宿主地址。
	prefix := netip.MustParsePrefix("198.19.0.0/30")
	if _, err := Assign(prefix, overlayPeers(t, 2)); err != nil {
		t.Fatalf("Assign with 2 peers into a /30: %v", err)
	}
	if _, err := Assign(prefix, overlayPeers(t, 3)); err == nil {
		t.Fatal("Assign into a /30 with 3 peers = nil, want error")
	}

	if _, err := Assign(netip.MustParsePrefix("198.19.0.0/31"), nil); err == nil {
		t.Error("Assign with a /31 = nil, want error")
	}
	if _, err := Assign(netip.MustParsePrefix("fd7a:115c:a1e0::/48"), nil); err == nil {
		t.Error("Assign with an IPv6 prefix = nil, want error")
	}
}

// TestAssignEmpty 固定"只做被访问方"的节点：没有对端时分配空表，不报错。
func TestAssignEmpty(t *testing.T) {
	o, err := Assign(netip.MustParsePrefix("198.19.0.0/24"), nil)
	if err != nil {
		t.Fatalf("Assign(nil): %v", err)
	}
	if len(o.Peers()) != 0 {
		t.Errorf("Peers() = %v, want empty", o.Peers())
	}
	if _, ok := o.Lookup("b"); ok {
		t.Error("Lookup hit on an empty overlay")
	}
	if o.Prefix() != netip.MustParsePrefix("198.19.0.0/24") {
		t.Errorf("Prefix() = %v", o.Prefix())
	}
}

// TestAssignPeersAreOrderedByAddress 固定 Peers() 的顺序稳定（按 overlay 地址
// 升序），使日志与测试断言可以依赖它。
func TestAssignPeersAreOrderedByAddress(t *testing.T) {
	peers := overlayPeers(t, 8)
	o, err := Assign(netip.MustParsePrefix("198.19.0.0/24"), peers)
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}

	got := o.Peers()
	if len(got) != len(peers) {
		t.Fatalf("Peers() returned %d entries, want %d", len(got), len(peers))
	}
	for i := 1; i < len(got); i++ {
		prev, _ := o.Addr(got[i-1].HostName)
		cur, _ := o.Addr(got[i].HostName)
		if prev.Compare(cur) > 0 {
			t.Fatalf("Peers() is not sorted by address: %v then %v", prev, cur)
		}
	}
}
