package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestResolveDERPAddr 固定服务端 DERP 地址的两个来源与推导规则。
//
// 服务端没有 servers[]，因此默认值只能自己推导：host 取 domain，port 取
// listen 的端口（DERP 就挂在这个 HTTPS 监听上）。推导不出来时必须报错，
// 绝不退回猜测值——一个猜错的中继地址会让每个节点都连不上。
func TestResolveDERPAddr(t *testing.T) {
	t.Run("显式配置优先", func(t *testing.T) {
		fc := &FileConfig{Server: ServerConfig{
			Domain: "example.com",
			Listen: ":443",
			VPN:    VPNConfig{DERPAddr: "relay.example.com:8443"},
		}}
		got, err := fc.ResolveDERPAddr()
		require.NoError(t, err)
		require.Equal(t, "relay.example.com:8443", got)
	})

	t.Run("从 domain 与 listen 推导", func(t *testing.T) {
		cases := []struct {
			listen string
			want   string
		}{
			{":443", "example.com:443"},
			{"0.0.0.0:8443", "example.com:8443"},
			{"[::]:443", "example.com:443"},
			{"192.0.2.1:9443", "example.com:9443"},
			// 服务名对 net.Listen 合法（Go 会解析成端口），因此推导也必须接受它，
			// 但结果要归一化成数字端口：对端只会把它读成 DERPPort int。
			{":https", "example.com:443"},
		}
		for _, tc := range cases {
			fc := &FileConfig{Server: ServerConfig{Domain: "example.com", Listen: tc.listen}}
			got, err := fc.ResolveDERPAddr()
			require.NoError(t, err, "listen %q", tc.listen)
			require.Equal(t, tc.want, got, "listen %q", tc.listen)
		}
	})

	t.Run("推导失败时必须报错并指向 derp_addr", func(t *testing.T) {
		cases := []struct {
			name   string
			server ServerConfig
		}{
			{"domain 为空", ServerConfig{Listen: ":443"}},
			{"listen 为空", ServerConfig{Domain: "example.com"}},
			{"listen 没有端口", ServerConfig{Domain: "example.com", Listen: "example.com"}},
			{"listen 的服务名不可解析", ServerConfig{Domain: "example.com", Listen: ":notaservice"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fc := &FileConfig{Server: tc.server}
				_, err := fc.ResolveDERPAddr()
				require.Error(t, err)
				require.Contains(t, err.Error(), "server.vpn.derp_addr")
			})
		}
	})

	t.Run("显式值本身非法时报错", func(t *testing.T) {
		for _, addr := range []string{"example.com", ":443", "example.com:", "example.com:https"} {
			fc := &FileConfig{Server: ServerConfig{
				Domain: "example.com",
				Listen: ":443",
				VPN:    VPNConfig{DERPAddr: addr},
			}}
			_, err := fc.ResolveDERPAddr()
			require.Error(t, err, "derp_addr %q", addr)
		}
	})
}

// TestLoadConfigValidatesVPN 固定 VPN 的校验发生在配置加载阶段，且只在
// vpn.enabled 时生效：一个未启用的 VPN 配置不参与运行期，不应阻止服务端启动。
func TestLoadConfigValidatesVPN(t *testing.T) {
	t.Run("启用且可推导时通过", func(t *testing.T) {
		fc, err := LoadConfig(writeConfig(t, `{
			"server": {"listen": ":8443", "domain": "example.com", "vpn": {"enabled": true}}
		}`))
		require.NoError(t, err)
		addr, err := fc.ResolveDERPAddr()
		require.NoError(t, err)
		require.Equal(t, "example.com:8443", addr)
	})

	t.Run("启用但推导不出端口时启动失败", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"listen": "example.com", "domain": "example.com", "vpn": {"enabled": true}}
		}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "server.vpn.derp_addr")
	})

	t.Run("启用但 domain 为空时启动失败", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"listen": ":443", "vpn": {"enabled": true}}
		}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "server.domain")
	})

	t.Run("启用且显式配置非法时启动失败", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"listen": ":443", "domain": "example.com", "vpn": {"enabled": true, "derp_addr": "example.com"}}
		}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "derp_addr")
	})

	t.Run("未启用时不校验", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"vpn": {"enabled": false, "derp_addr": "not-a-host-port"}}
		}`))
		require.NoError(t, err)
	})
}

// TestResolveDERPAddrIsIdempotent 守护"推导结果本身可再次解析"：调用方拿到
// host:port 之后要交给 net.SplitHostPort 拆成 DERPMap 的 HostName 与 DERPPort，
// 推导与显式配置两条路径必须给出同一种形态。
func TestResolveDERPAddrIsIdempotent(t *testing.T) {
	fc := &FileConfig{Server: ServerConfig{Domain: "example.com", Listen: ":8443"}}
	addr, err := fc.ResolveDERPAddr()
	require.NoError(t, err)

	fc.Server.VPN.DERPAddr = addr
	again, err := fc.ResolveDERPAddr()
	require.NoError(t, err)
	require.Equal(t, addr, again)
}

// TestExampleConfigVPNIsResolvable 守护示例里的 VPN 配置本身可用：设计文档与
// 示例给出的默认值不会与运行期的推导规则漂移。
//
// enabled 在示例里是 false（内嵌 DERP 会把该服务端变成节点组网的中继，运维应当
// 自己打开它——见 ExampleConfig 的注释），但 derp_addr 仍然写全，因此"照抄示例后
// 只把 enabled 改成 true"必须能直接启动。
func TestExampleConfigVPNIsResolvable(t *testing.T) {
	fc := ExampleConfig()
	require.False(t, fc.Server.VPN.Enabled, "the example must not enable the relay by default")
	fc.Server.VPN.Enabled = true
	addr, err := fc.ResolveDERPAddr()
	require.NoError(t, err)
	require.Equal(t, "your-domain.com:443", addr)
}
