package vpnnode

import (
	"strings"
	"testing"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/vpn"
)

func newConnInfo(regions []*tailcfg.DERPRegion, regionID tailcfg.DERPRegionID, withDisco bool) *tailcat.ConnInfo {
	ci := tailcat.ConnInfo{
		ServerPublic: tailcat.NodePublic{NodePublic: key.NewNode().Public()},
		PresharedKey: tailcat.NewPresharedKey(),
		Region:       regions,
		RegionID:     regionID,
	}
	if withDisco {
		ci.ServerDiscoPublic = tailcat.DiscoPublic{DiscoPublic: key.NewDisco().Public()}
	}
	return &ci
}

// fullAddr 构造一个完整展开格式的地址，其 region 由本包的 vpn.BuildRegion 生成——
// 也就是说这是对端面真实会打印出来的那种地址。多个 derpAddr 就是同一 region 下的
// 多个中继节点。
func fullAddr(t *testing.T, derpAddrs ...string) string {
	t.Helper()
	region, err := vpn.BuildRegion(derpAddrs...)
	if err != nil {
		t.Fatalf("vpn.BuildRegion(%q): %v", derpAddrs, err)
	}
	return string(newConnInfo([]*tailcfg.DERPRegion{region}, 0, true).Addr())
}

// TestAssertPeersShareDERPSet 固定"双方必须声明同一组中继"这条启动期校验：它是
// DERP 私有化的直接推论（内嵌 DERP 只接待经本服务端隧道送达的连接，所以只有集合
// 相等才保证"无论隧道落在哪台服务端，地址里都有它"）。顺序与书写差异不算不一致，
// 缺一个/多一个都必须在启动时被点名拒绝。
func TestAssertPeersShareDERPSet(t *testing.T) {
	own := []string{"relay-a.example.com:443", "relay-b.example.com:8443"}

	t.Run("集合相同且顺序不同也通过", func(t *testing.T) {
		peer := PeerRef{HostName: "b", Address: fullAddr(t, "relay-b.example.com:8443", "Relay-A.Example.com:443")}
		if err := assertPeersShareDERPSet(own, []PeerRef{peer}); err != nil {
			t.Errorf("assertPeersShareDERPSet: %v", err)
		}
	})

	t.Run("单节点旧形态", func(t *testing.T) {
		single := []string{"relay.example.com:8443"}
		peer := PeerRef{HostName: "b", Address: fullAddr(t, "relay.example.com:8443")}
		if err := assertPeersShareDERPSet(single, []PeerRef{peer}); err != nil {
			t.Errorf("assertPeersShareDERPSet: %v", err)
		}
	})

	t.Run("对端少一个节点时报错并点名", func(t *testing.T) {
		peer := PeerRef{HostName: "b", Address: fullAddr(t, "relay-a.example.com:443")}
		err := assertPeersShareDERPSet(own, []PeerRef{peer})
		if err == nil {
			t.Fatal("assertPeersShareDERPSet = nil, want an error for a missing relay")
		}
		for _, want := range []string{"b", "relay-b.example.com:8443", "relay-a.example.com:443"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should mention %q", err, want)
			}
		}
	})

	t.Run("对端多一个节点时报错并点名", func(t *testing.T) {
		peer := PeerRef{HostName: "b", Address: fullAddr(t, own[0], own[1], "relay-c.example.com:443")}
		err := assertPeersShareDERPSet(own, []PeerRef{peer})
		if err == nil {
			t.Fatal("assertPeersShareDERPSet = nil, want an error for an extra relay")
		}
		if !strings.Contains(err.Error(), "relay-c.example.com:443") {
			t.Errorf("error %q should name the extra relay", err)
		}
	})

	t.Run("本节点列表为空或非法时报错", func(t *testing.T) {
		peer := PeerRef{HostName: "b", Address: fullAddr(t, own[0])}
		if err := assertPeersShareDERPSet(nil, []PeerRef{peer}); err == nil {
			t.Error("assertPeersShareDERPSet(nil, ...) = nil, want an error")
		}
		if err := assertPeersShareDERPSet([]string{"not-an-addr"}, []PeerRef{peer}); err == nil {
			t.Error("assertPeersShareDERPSet(invalid, ...) = nil, want an error")
		}
	})

	t.Run("没有对端时无从比较", func(t *testing.T) {
		if err := assertPeersShareDERPSet(own, nil); err != nil {
			t.Errorf("assertPeersShareDERPSet(own, nil) = %v, want nil", err)
		}
		// 空列表本身由 NewConfig 更早地拒绝（"没有任何中继被声明"），这里没有对端
		// 就无从比较，因此不算错误。
		if err := assertPeersShareDERPSet(nil, nil); err != nil {
			t.Errorf("assertPeersShareDERPSet(nil, nil) = %v, want nil", err)
		}
		// 但一旦有对端，集合差异立刻暴露：空列表 + 声明了一个中继的对端 = 不一致。
		peer := PeerRef{HostName: "b", Address: fullAddr(t, "relay-a.example.com:443")}
		if err := assertPeersShareDERPSet(nil, []PeerRef{peer}); err == nil {
			t.Error("assertPeersShareDERPSet(nil, [peer]) = nil, want an error")
		}
	})
}

// TestBuildRegionRoundTripsThroughAddr 是"零控制面"的核心断言：由 vpn.BuildRegion
// 构造的 region 序列化进 tailcat 地址、再解析出来之后，对端需要的一切（DERP
// 主机与端口）都还在地址里，且 region 非空——也就是客户端不需要查询任何
// DERPMap。
func TestBuildRegionRoundTripsThroughAddr(t *testing.T) {
	addr := fullAddr(t, "relay.example.com:8443")

	ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if len(ci.Region) == 0 {
		t.Fatal("parsed address has no embedded region: this is the short (non self-contained) form")
	}
	nodes := ci.Region[0].Nodes
	if len(nodes) != 1 {
		t.Fatalf("parsed region has %d nodes, want 1", len(nodes))
	}
	if nodes[0].HostName != "relay.example.com" || nodes[0].DERPPort != 8443 {
		t.Errorf("parsed node = %s:%d, want relay.example.com:8443", nodes[0].HostName, nodes[0].DERPPort)
	}

	// Expand 对完整格式必须是 no-op：它一旦真的去取 DERPMap 就会联网。
	if err := ci.Expand(t.Context()); err != nil {
		t.Fatalf("Expand on a fully expanded address: %v", err)
	}
}

// TestAssertFullAddr 固定 4.7 的硬契约：完整展开格式被接受，短格式（只带
// region ID）必须被拒且错误信息指向官方 DERPMap，其余不完整形态也一并被拒。
func TestAssertFullAddr(t *testing.T) {
	t.Run("接受完整展开格式", func(t *testing.T) {
		if err := AssertFullAddr(fullAddr(t, "relay.example.com:8443")); err != nil {
			t.Fatalf("AssertFullAddr(full) = %v, want nil", err)
		}
	})

	t.Run("接受端口为 443 的完整格式", func(t *testing.T) {
		if err := AssertFullAddr(fullAddr(t, "relay.example.com:443")); err != nil {
			t.Fatalf("AssertFullAddr(full, port 443) = %v, want nil", err)
		}
	})

	t.Run("拒绝短格式并点名官方 DERPMap", func(t *testing.T) {
		short := string(newConnInfo(nil, vpn.RegionID, true).Addr())
		err := AssertFullAddr(short)
		if err == nil {
			t.Fatal("AssertFullAddr(short) = nil, want error")
		}
		if !strings.Contains(err.Error(), tailcat.DefaultDERPMapURL) {
			t.Errorf("error %q should mention %s", err, tailcat.DefaultDERPMapURL)
		}
		if !strings.Contains(err.Error(), "not fully expanded") {
			t.Errorf("error %q should say the address is not fully expanded", err)
		}
	})

	t.Run("拒绝缺少 disco 公钥的旧地址", func(t *testing.T) {
		region, err := vpn.BuildRegion("relay.example.com:8443")
		if err != nil {
			t.Fatal(err)
		}
		legacy := string(newConnInfo([]*tailcfg.DERPRegion{region}, 0, false).Addr())
		if err := AssertFullAddr(legacy); err == nil {
			t.Fatal("AssertFullAddr(legacy) = nil, want error")
		}
	})

	t.Run("拒绝没有节点的 region", func(t *testing.T) {
		region := &tailcfg.DERPRegion{RegionID: vpn.RegionID, RegionCode: vpn.RegionCode, RegionName: vpn.RegionName}
		addr := string(newConnInfo([]*tailcfg.DERPRegion{region}, 0, true).Addr())
		if err := AssertFullAddr(addr); err == nil {
			t.Fatal("AssertFullAddr(region without nodes) = nil, want error")
		}
	})

	t.Run("拒绝没有主机名的节点", func(t *testing.T) {
		region := &tailcfg.DERPRegion{
			RegionID: vpn.RegionID,
			Nodes:    []*tailcfg.DERPNode{{Name: vpn.DERPNodeName, RegionID: vpn.RegionID, DERPPort: 443}},
		}
		addr := string(newConnInfo([]*tailcfg.DERPRegion{region}, 0, true).Addr())
		if err := AssertFullAddr(addr); err == nil {
			t.Fatal("AssertFullAddr(node without host name) = nil, want error")
		}
	})

	t.Run("拒绝空值与非法值", func(t *testing.T) {
		for _, addr := range []string{"", "not-a-tailcat-address", "tc!!!", "tcFULL"} {
			if err := AssertFullAddr(addr); err == nil {
				t.Errorf("AssertFullAddr(%q) = nil, want error", addr)
			}
		}
	})
}
