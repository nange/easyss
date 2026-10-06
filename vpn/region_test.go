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

// TestRegionIDIsNotZero 约束 region 编号常量本身可用。
func TestRegionIDIsNotZero(t *testing.T) {
	if RegionID == 0 {
		t.Fatal("RegionID must be non-zero: tailcat.Server.Start rejects RegionID 0")
	}
	if RegionID != sharedconfig.DefaultVPNRegionID {
		t.Errorf("RegionID = %d, want sharedconfig.DefaultVPNRegionID %d", RegionID, sharedconfig.DefaultVPNRegionID)
	}
}
