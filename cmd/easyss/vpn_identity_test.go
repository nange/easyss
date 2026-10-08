package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/runner"
	"github.com/stretchr/testify/require"
)

// TestWriteVPNIdentity 固定 `-show-vpn-identity` 的输出契约：
//
//   - client nodekey 与地址分别打印，并各自说明该填到对端的哪个字段；
//   - 地址里内嵌的中继节点单独列出来（地址本身是不可读的 base64，运维需要一眼看出
//     它包含几个中继、顺序如何）；
//   - "当前服务端不在声明的中继列表里"只作为一行 warning：地址依然要打印出来，
//     因为运维正需要它去配对端，而 VPN 能否工作由启动路径决定（见 runner.vpnOptions）。
func TestWriteVPNIdentity(t *testing.T) {
	id := &runner.VPNIdentity{
		ClientNodeKey: "nodekey:abc",
		TailcatAddr:   "tcFULLADDRESS",
		DERPNodes:     []string{"relay-a.example.com:443", "relay-b.example.com:8443"},
	}

	t.Run("没有问题时只打印身份与节点列表", func(t *testing.T) {
		var b strings.Builder
		require.NoError(t, writeVPNIdentity(&b, id, nil))
		out := b.String()
		for _, want := range []string{
			"nodekey:abc",
			"tcFULLADDRESS",
			"relay-a.example.com:443, relay-b.example.com:8443",
			"vpn.allow_clients",
			"vpn.peers[].address",
			"it is a secret",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output %q should mention %q", out, want)
			}
		}
		if strings.Contains(out, "warning:") {
			t.Errorf("output contains a warning although the config is consistent: %q", out)
		}
	})

	t.Run("当前服务端不是中继时仍然打印地址并给出 warning", func(t *testing.T) {
		var b strings.Builder
		require.NoError(t, writeVPNIdentity(&b, id, errors.New("the current server c.example.com:443 is not one of the DERP relays")))
		out := b.String()
		if !strings.Contains(out, "tcFULLADDRESS") {
			t.Errorf("the address must stay printable for troubleshooting: %q", out)
		}
		if !strings.Contains(out, "warning:") || !strings.Contains(out, "c.example.com:443") {
			t.Errorf("output should carry a warning naming the server: %q", out)
		}
		if !strings.Contains(out, "vpn will not work") {
			t.Errorf("the warning should state the consequence: %q", out)
		}
	})

	t.Run("推导不出地址时给出原因且不打印节点列表", func(t *testing.T) {
		broken := &runner.VPNIdentity{ClientNodeKey: "nodekey:abc", AddrErr: errors.New("no DERP relay is declared")}
		var b strings.Builder
		require.NoError(t, writeVPNIdentity(&b, broken, nil))
		out := b.String()
		if !strings.Contains(out, "unavailable") || !strings.Contains(out, "no DERP relay is declared") {
			t.Errorf("output should explain why the address is unavailable: %q", out)
		}
		if strings.Contains(out, "derp nodes in the address") {
			t.Errorf("there is no address, so no relay list should be printed: %q", out)
		}
	})
}
