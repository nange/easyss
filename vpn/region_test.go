package vpn

import (
	"testing"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// TestBuildRegion 固定内嵌 region 的形态：region 编号非零（tailcat 会把 0 当成
// "未设置"），节点带上 derp_addr 拆出的 HostName 与 DERPPort（对端据此直连，
// 不做任何 DERPMap 查询）。
func TestBuildRegion(t *testing.T) {
	region, err := BuildRegion("relay.example.com:8443")
	if err != nil {
		t.Fatalf("BuildRegion: %v", err)
	}
	if region.RegionID == 0 {
		t.Fatal("RegionID = 0, tailcat treats it as unset")
	}
	if region.RegionID != RegionID {
		t.Errorf("RegionID = %d, want %d", region.RegionID, RegionID)
	}
	if len(region.Nodes) != 1 {
		t.Fatalf("Nodes = %d, want 1", len(region.Nodes))
	}
	node := region.Nodes[0]
	if node.HostName != "relay.example.com" {
		t.Errorf("HostName = %q, want relay.example.com", node.HostName)
	}
	if node.DERPPort != 8443 {
		t.Errorf("DERPPort = %d, want 8443", node.DERPPort)
	}
	if node.RegionID != RegionID {
		t.Errorf("node RegionID = %d, want %d", node.RegionID, RegionID)
	}

	t.Run("端口非法时报错", func(t *testing.T) {
		for _, addr := range []string{"", "relay.example.com", ":443", "relay.example.com:", "relay.example.com:https", "relay.example.com:0", "relay.example.com:70000"} {
			if _, err := BuildRegion(addr); err == nil {
				t.Errorf("BuildRegion(%q) = nil error, want error", addr)
			}
		}
	})
}

// TestBuildRegionMultipleNodes 固定"同一 region 下的多个中继节点"这一形态：节点
// 按传入顺序排列（tailcat 按 `reg.Nodes` 顺序尝试，第一个连上的胜出），每个节点
// 带自己的 HostName/DERPPort，节点名唯一（编码进地址时会被抹掉，仅供本机排障）。
func TestBuildRegionMultipleNodes(t *testing.T) {
	region, err := BuildRegion("relay-a.example.com:443", "relay-b.example.com:8443", "[2001:db8::1]:9443")
	if err != nil {
		t.Fatalf("BuildRegion: %v", err)
	}
	if region.RegionID != RegionID {
		t.Errorf("RegionID = %d, want %d", region.RegionID, RegionID)
	}
	if len(region.Nodes) != 3 {
		t.Fatalf("Nodes = %d, want 3", len(region.Nodes))
	}
	wantHosts := []string{"relay-a.example.com", "relay-b.example.com", "2001:db8::1"}
	wantPorts := []int{443, 8443, 9443}
	names := make(map[string]struct{}, len(region.Nodes))
	for i, node := range region.Nodes {
		if node.HostName != wantHosts[i] || node.DERPPort != wantPorts[i] {
			t.Errorf("node %d = %s:%d, want %s:%d", i, node.HostName, node.DERPPort, wantHosts[i], wantPorts[i])
		}
		if node.RegionID != RegionID {
			t.Errorf("node %d RegionID = %d, want %d", i, node.RegionID, RegionID)
		}
		if _, dup := names[node.Name]; dup {
			t.Errorf("node %d reuses the name %q; netcheck identifies nodes by name", i, node.Name)
		}
		names[node.Name] = struct{}{}
	}

	t.Run("单节点沿用固定名字", func(t *testing.T) {
		single, err := BuildRegion("relay.example.com:443")
		if err != nil {
			t.Fatalf("BuildRegion: %v", err)
		}
		if got := single.Nodes[0].Name; got != DERPNodeName {
			t.Errorf("single-node region name = %q, want %q", got, DERPNodeName)
		}
	})

	t.Run("空列表报错", func(t *testing.T) {
		if _, err := BuildRegion(); err == nil {
			t.Error("BuildRegion() = nil error, want an error: a region needs at least one node")
		}
	})

	t.Run("重复节点报错", func(t *testing.T) {
		for _, addrs := range [][]string{
			{"relay.example.com:443", "relay.example.com:443"},
			{"relay.example.com:443", "Relay.Example.com:443"},
		} {
			if _, err := BuildRegion(addrs...); err == nil {
				t.Errorf("BuildRegion(%v) = nil error, want an error for a duplicated relay", addrs)
			}
		}
	})
}

// TestRegionIDIsNotZero 约束 region 编号常量本身可用。
func TestRegionIDIsNotZero(t *testing.T) {
	if RegionID == 0 {
		t.Fatal("RegionID must be non-zero: tailcat.Server.Start rejects RegionID 0")
	}
	if RegionID != sharedconfig.DefaultVPNRegionID {
		t.Errorf("RegionID = %d, want sharedconfig.DefaultVPNRegionID %d", RegionID, sharedconfig.DefaultVPNRegionID)
	}
}
