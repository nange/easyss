package tunhelper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRoutePrintResidue(t *testing.T) {
	const (
		tunGW    = "198.18.0.1"
		physGW   = "192.168.1.1"
		routeOut = `
===========================================================================
Interface List
 12...00 ff a1 b2 c3 d4 ......Wintun Userspace Tunnel
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.20     25
          1.0.0.0        255.0.0.0       198.18.0.1       198.18.0.1      5
          2.0.0.0        254.0.0.0       198.18.0.1       198.18.0.1      5
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        192.168.1.0    255.255.255.0         On-link     192.168.1.20    281
===========================================================================
Persistent Routes:
  None
`
	)

	detail, leftover := parseRoutePrintResidue(routeOut, tunGW)
	require.True(t, leftover)
	require.Contains(t, detail, "1.0.0.0")
	require.Contains(t, detail, tunGW)

	_, leftover = parseRoutePrintResidue(routeOut, physGW)
	require.False(t, leftover, "物理默认路由不是 TUN 残留")

	_, leftover = parseRoutePrintResidue(routeOut, "")
	require.False(t, leftover, "空网关不能当作匹配条件")

	// 同一条指向 TUN 网关的路由若不属于创建脚本安装的 8 个目标，关闭脚本不会删它，
	// 复核也不能把它算成自己的残留。
	_, leftover = parseRoutePrintResidue(
		"          9.9.9.0    255.255.255.0       198.18.0.1       198.18.0.1      5\n",
		tunGW,
	)
	require.False(t, leftover)
}

func TestIsWindowsSplitRoute(t *testing.T) {
	for _, dst := range []string{"1.0.0.0", "2.0.0.0", "4.0.0.0", "8.0.0.0", "16.0.0.0", "32.0.0.0", "64.0.0.0", "128.0.0.0"} {
		require.True(t, isWindowsSplitRoute(dst), dst)
	}
	for _, dst := range []string{"", "0.0.0.0", "255.255.255.255", "9.9.9.0"} {
		require.False(t, isWindowsSplitRoute(dst), dst)
	}
}
