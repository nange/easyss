package vpnnode

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/types/key"
)

// Overlay 把对端映射到 overlay 段内的虚拟 IPv4。
//
// 这些地址是**访问侧本地的概念**：TUN 模式下用来回答对端名字的 DNS 查询，以及
// 让 tun2socks 有一条可路由的目标 IP；它们不进隧道、对端永远看不到（见
// docs/vpn-design.md 5.1）。因此不同节点上的 overlay 段不需要一致。
//
// 分配是**确定性**的：同一个对端在任何一次启动、任何一台机器上都得到同一个地址
// （只由它的 tailcat 公钥决定），因为"地址变化"会让 DNS 缓存与用户笔记同时失效。
type Overlay struct {
	prefix netip.Prefix
	// byName 的键是 host_name 的小写形式：DNS 名字本身不区分大小写。
	byName map[string]peerOverlay
	byAddr map[netip.Addr]peerOverlay
}

// peerOverlay 是一个对端在 overlay 里的完整映射。
type peerOverlay struct {
	ref  PeerRef
	addr netip.Addr
}

// Assign 在 prefix 内为每个对端分配一个确定的 overlay 地址。
//
// 分配规则：按对端公钥排序（使结果与配置里的书写顺序无关），再以公钥的 FNV-1a
// 哈希对可用地址数取模得到首选槽位，冲突时线性探测下一个槽位。这样即使两个
// 公钥的值相近，结果也只取决于 peers 这个集合本身。
//
// 要求每个对端都是完整展开格式的 tailcat 地址——公钥是分配的唯一输入，因此传入
// 的 peers 应当已经过 NewConfig 的校验。
func Assign(prefix netip.Prefix, peers []PeerRef) (*Overlay, error) {
	capacity, base, err := overlayRange(prefix)
	if err != nil {
		return nil, err
	}

	type entry struct {
		peer PeerRef
		pub  key.NodePublic
		hash uint64
	}
	entries := make([]entry, 0, len(peers))
	for _, p := range peers {
		ci, err := tailcat.ParseAddr(tailcat.Addr(p.Address))
		if err != nil {
			return nil, fmt.Errorf("vpn: peer %q: invalid tailcat address: %w", p.HostName, err)
		}
		pub := ci.ServerPublic.NodePublic
		if pub.IsZero() {
			return nil, fmt.Errorf("vpn: peer %q: tailcat address carries no server public key", p.HostName)
		}
		h := fnv.New64a()
		// 用 AppendTo（32 字节原始值）而不是已废弃的 Raw32：前者是上游推荐的
		// 取原始字节的方式，也不需要额外的临时数组。
		_, _ = h.Write(pub.AppendTo(nil))
		entries = append(entries, entry{peer: p, pub: pub, hash: h.Sum64()})
	}

	slices.SortFunc(entries, func(a, b entry) int {
		switch {
		case a.pub.Less(b.pub):
			return -1
		case b.pub.Less(a.pub):
			return 1
		default:
			return 0
		}
	})

	o := &Overlay{
		prefix: prefix,
		byName: make(map[string]peerOverlay, len(entries)),
		byAddr: make(map[netip.Addr]peerOverlay, len(entries)),
	}

	used := make([]bool, capacity)
	for i, e := range entries {
		// 排序后公钥相同的条目必然相邻：两个 host_name 指向同一个节点时，
		// 给它们两个 overlay 地址只会让用户以为那是两台机器。
		if i > 0 && !entries[i-1].pub.Less(e.pub) {
			return nil, fmt.Errorf("vpn: peers %q and %q point at the same node (identical tailcat public key); "+
				"give each peer a distinct address", entries[i-1].peer.HostName, e.peer.HostName)
		}
		slot, err := freeSlot(used, e.hash, capacity)
		if err != nil {
			return nil, fmt.Errorf("vpn: overlay %s cannot hold %d peers: %w", prefix, len(entries), err)
		}
		used[slot] = true

		po := peerOverlay{ref: e.peer, addr: addrAt(base, slot)}
		o.byName[strings.ToLower(e.peer.HostName)] = po
		o.byAddr[po.addr] = po
	}
	return o, nil
}

// Prefix 返回 overlay 段。
func (o *Overlay) Prefix() netip.Prefix { return o.prefix }

// Addr 返回对端的 overlay 地址。
func (o *Overlay) Addr(hostName string) (netip.Addr, bool) {
	po, ok := o.byName[strings.ToLower(hostName)]
	if !ok {
		return netip.Addr{}, false
	}
	return po.addr, true
}

// Lookup 按 host_name（不区分大小写）或 overlay 字面 IP 查找对端。
//
// 这两条路径正是访问侧的全部入口：应用书写的名字（ssh user@b）经本地 DNS 解析
// 成 overlay IP，TUN 模式下则直接以 overlay IP 到达 SOCKS5，因此两处都必须命中。
func (o *Overlay) Lookup(host string) (PeerRef, bool) {
	// 名字按 DNS 的写法比较：不区分大小写，并去掉末尾的根点（"b." 与 "b" 是同一个
	// 名字）。配置侧的 host_name 已在 normalizePeers 里归一化，这里再兜一层是为了
	// 覆盖"应用直接写 FQDN"的情形。
	if po, ok := o.byName[strings.ToLower(trimDNSRoot(host))]; ok {
		return po.ref, true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return PeerRef{}, false
	}
	po, ok := o.byAddr[addr.Unmap()]
	return po.ref, ok
}

// Peers 返回按 overlay 地址升序排列的全部对端。顺序稳定，便于日志与测试断言。
func (o *Overlay) Peers() []PeerRef {
	out := make([]peerOverlay, 0, len(o.byAddr))
	for _, po := range o.byAddr {
		out = append(out, po)
	}
	slices.SortFunc(out, func(a, b peerOverlay) int { return a.addr.Compare(b.addr) })

	refs := make([]PeerRef, 0, len(out))
	for _, po := range out {
		refs = append(refs, po.ref)
	}
	return refs
}

// overlayRange 校验 overlay 段并返回可用地址数与其网络地址。
//
// 可用的宿主地址排除网络地址与广播地址：overlay 地址不会真的出现在任何链路层上，
// 因此"广播"在技术上无害，但把它们排除掉能让 198.19.0.0 与 198.19.0.255 这两个
// 容易被误读的地址永远不出现。
func overlayRange(prefix netip.Prefix) (capacity int, base uint32, err error) {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return 0, 0, fmt.Errorf("vpn: invalid IPv4 overlay prefix %v", prefix)
	}
	bits := 32 - prefix.Bits()
	if bits < 2 {
		return 0, 0, fmt.Errorf("vpn: overlay prefix %v leaves no usable host addresses", prefix)
	}
	a4 := prefix.Masked().Addr().As4()
	return (1 << bits) - 2, binary.BigEndian.Uint32(a4[:]), nil
}

// freeSlot 从 hash%capacity 开始线性探测第一个空槽位。
func freeSlot(used []bool, hash uint64, capacity int) (int, error) {
	start := int(hash % uint64(capacity))
	for i := range capacity {
		slot := (start + i) % capacity
		if !used[slot] {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("no free address left")
}

// addrAt 返回 base+i 的 IPv4 地址（i 从 0 开始，对应第一个可用宿主地址）。
func addrAt(base uint32, i int) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], base+uint32(i)+1)
	return netip.AddrFrom4(b)
}
