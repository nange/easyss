package config

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// lockedLogBuffer 是并发安全的日志 sink（配置加载本身单线程，但日志器是进程级的，
// 这里保持与生产路径同样的谨慎）。
type lockedLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedLogBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLogs 把 easyss 的日志器换成写入 lockedLogBuffer 的 slog，返回该缓冲
// （恢复由 t.Cleanup 完成）。
func captureLogs(t *testing.T) *lockedLogBuffer {
	t.Helper()
	buf := new(lockedLogBuffer)
	prev := log.Logger()
	log.SetLogger(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { log.SetLogger(prev) })
	return buf
}

// TestResolveDERPAddr 固定服务端 DERP 地址的唯一来源与推导规则。
//
// 服务端没有 servers[]，地址只能自己推导：host 取 domain，port 取 listen 的端口
// （DERP 就挂在这个 HTTPS 监听上）。推导不出来时必须报错，绝不退回猜测值——一个
// 猜错的中继地址会让每个节点都连不上。
//
// 这里刻意没有"显式覆盖"的配置项：内嵌 DERP 的对外地址必须与它实际监听的
// host:port 一致（服务端靠完全匹配把它认成"来访问我的 DERP"并改拨回环），端口
// 转发/反向代理那类形态因此明确不支持。
func TestResolveDERPAddr(t *testing.T) {
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

	t.Run("推导失败时报出缺的是哪一项", func(t *testing.T) {
		cases := []struct {
			name   string
			server ServerConfig
			want   string
		}{
			{"domain 为空", ServerConfig{Listen: ":443"}, "server.domain"},
			{"listen 为空", ServerConfig{Domain: "example.com"}, "server.listen"},
			{"listen 没有端口", ServerConfig{Domain: "example.com", Listen: "example.com"}, "server.listen"},
			{"listen 的服务名不可解析", ServerConfig{Domain: "example.com", Listen: ":notaservice"}, "server.listen"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fc := &FileConfig{Server: tc.server}
				_, err := fc.ResolveDERPAddr()
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.want)
			})
		}
	})
}

// TestLoadConfigWarnsOnRemovedDERPAddr 固定已移除字段的降级行为：配置里残留的
// server.vpn.derp_addr 既不影响推导结果（它是未知键，被忽略），也不会让启动失败，
// 但必须在启动日志里说清楚——"以为中继在别的 host:port"正是那种启动成功、VPN 却
// 一直连不上的配置。
func TestLoadConfigWarnsOnRemovedDERPAddr(t *testing.T) {
	logs := captureLogs(t)

	fc, err := LoadConfig(writeConfig(t, `{
		"server": {"listen": ":8443", "domain": "example.com", "vpn": {
			"enabled": true, "derp_addr": "relay.internal:9443"
		}}
	}`))
	require.NoError(t, err)

	addr, err := fc.ResolveDERPAddr()
	require.NoError(t, err)
	require.Equal(t, "example.com:8443", addr, "the removed key must not influence the derived address")

	out := logs.String()
	require.Contains(t, out, "server.vpn.derp_addr was removed")
	require.Contains(t, out, "relay.internal:9443")
}

// TestLoadConfigWithoutDERPAddrKeyStaysQuiet 守护告警不误报：没有那个键的配置
// 不该出现任何相关日志。
func TestLoadConfigWithoutDERPAddrKeyStaysQuiet(t *testing.T) {
	logs := captureLogs(t)

	_, err := LoadConfig(writeConfig(t, `{
		"server": {"listen": ":8443", "domain": "example.com", "vpn": {"enabled": true}}
	}`))
	require.NoError(t, err)
	require.NotContains(t, logs.String(), "derp_addr")
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
		require.Contains(t, err.Error(), "server.listen")
	})

	t.Run("启用但 domain 为空时启动失败", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"listen": ":443", "vpn": {"enabled": true}}
		}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "server.domain")
	})

	t.Run("未启用时不校验", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"listen": "example.com", "vpn": {"enabled": false}}
		}`))
		require.NoError(t, err)
	})
}

// TestLoadConfigValidatesVPNMesh 固定 server.vpn 的 mesh 校验矩阵：mesh_key 与
// mesh_peers 必须成对出现、对端不能是自己也不能重复、每个对端都必须有一条经
// easyss 隧道的出网路径（自带 proxy 或全局 next_proxy.url）——内嵌 DERP 只在回环
// 上被服务，直连对端公网端口只会拿到伪装页，因此"没有代理"不是一种可工作的配置。
func TestLoadConfigValidatesVPNMesh(t *testing.T) {
	base := func(mesh string) string {
		return `{
			"server": {
				"listen": ":443", "domain": "a.example.com", "vpn": {"enabled": true` + mesh + `}
			}
		}`
	}

	t.Run("完整的 mesh 配置通过", func(t *testing.T) {
		fc, err := LoadConfig(writeConfig(t, `{
			"server": {
				"listen": ":443", "domain": "a.example.com", "vpn": {
					"enabled": true, "mesh_key": "shared-passphrase",
					"mesh_peers": [
						{"addr": "b.example.com:443", "proxy": "socks5://127.0.0.1:1081"},
						{"addr": "c.example.com:443"}
					]
				}
			},
			"next_proxy": {"url": "socks5://127.0.0.1:1082"}
		}`))
		require.NoError(t, err)
		require.Len(t, fc.Server.VPN.MeshPeers, 2)
	})

	t.Run("只有 mesh_key 或只有 mesh_peers 都报错", func(t *testing.T) {
		for _, mesh := range []string{
			`, "mesh_key": "shared-passphrase"`,
			`, "mesh_peers": [{"addr": "b.example.com:443", "proxy": "socks5://127.0.0.1:1081"}]`,
		} {
			_, err := LoadConfig(writeConfig(t, base(mesh)))
			require.Error(t, err, "mesh %q", mesh)
			require.Contains(t, err.Error(), "server.vpn.mesh")
		}
	})

	t.Run("VPN 未启用时配了 mesh 报错", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"listen": ":443", "domain": "a.example.com", "vpn": {
				"enabled": false, "mesh_key": "k", "mesh_peers": [{"addr": "b.example.com:443", "proxy": "socks5://127.0.0.1:1081"}]
			}}
		}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "enabled")
	})

	t.Run("空 mesh_key 报错", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, base(`,
			"mesh_key": "   ",
			"mesh_peers": [{"addr": "b.example.com:443", "proxy": "socks5://127.0.0.1:1081"}]`)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "mesh_key")
	})

	t.Run("对端地址非法/自连/重复都报错", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			peers string
		}{
			{"非法地址", `[{"addr": "b.example.com", "proxy": "socks5://127.0.0.1:1081"}]`},
			{"自连", `[{"addr": "a.example.com:443", "proxy": "socks5://127.0.0.1:1081"}]`},
			{"大小写不同的自连", `[{"addr": "A.Example.com:443", "proxy": "socks5://127.0.0.1:1081"}]`},
			{"重复对端", `[{"addr": "b.example.com:443", "proxy": "socks5://127.0.0.1:1081"}, {"addr": "b.example.com:443", "proxy": "socks5://127.0.0.1:1082"}]`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := LoadConfig(writeConfig(t, base(`,
					"mesh_key": "shared-passphrase",
					"mesh_peers": `+tc.peers)))
				require.Error(t, err)
				require.Contains(t, err.Error(), "mesh_peers")
			})
		}
	})

	t.Run("没有 proxy 且没有 next_proxy.url 时报错", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, base(`,
			"mesh_key": "shared-passphrase",
			"mesh_peers": [{"addr": "b.example.com:443"}]`)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "next_proxy.url")
	})

	t.Run("没有 proxy 但有 next_proxy.url 时通过", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"listen": ":443", "domain": "a.example.com", "vpn": {
				"enabled": true, "mesh_key": "shared-passphrase",
				"mesh_peers": [{"addr": "b.example.com:443"}]
			}},
			"next_proxy": {"url": "socks5://127.0.0.1:1081"}
		}`))
		require.NoError(t, err)
	})

	t.Run("非 socks5 的 proxy 报错", func(t *testing.T) {
		for _, proxy := range []string{"http://127.0.0.1:8080", "socks5://", "::::"} {
			_, err := LoadConfig(writeConfig(t, base(`,
				"mesh_key": "shared-passphrase",
				"mesh_peers": [{"addr": "b.example.com:443", "proxy": "`+proxy+`"}]`)))
			require.Error(t, err, "proxy %q", proxy)
		}
	})

	t.Run("mesh_peers[].ca_file 按可执行文件目录解析", func(t *testing.T) {
		fc, err := LoadConfig(writeConfig(t, base(`,
			"mesh_key": "shared-passphrase",
			"mesh_peers": [{"addr": "b.example.com:443", "proxy": "socks5://127.0.0.1:1081", "ca_file": "mesh-ca.pem"}]`)))
		require.NoError(t, err)
		require.True(t, filepath.IsAbs(fc.Server.VPN.MeshPeers[0].CAFile),
			"ca_file %q should be resolved to an absolute path", fc.Server.VPN.MeshPeers[0].CAFile)
	})
}

// TestResolveDERPAddrIsUsableDownstream 守护"推导结果本身就是一个合法的
// host:port"：调用方拿到它之后要交给 net.SplitHostPort 拆成 DERPMap 的 HostName
// 与 DERPPort（见 vpn.BuildRegion），而且它是纯推导——同样的输入必须给出同样的
// 结果。
func TestResolveDERPAddrIsUsableDownstream(t *testing.T) {
	fc := &FileConfig{Server: ServerConfig{Domain: "example.com", Listen: ":8443"}}
	addr, err := fc.ResolveDERPAddr()
	require.NoError(t, err)

	da, err := sharedconfig.SplitDERPAddr(addr)
	require.NoError(t, err)
	require.Equal(t, "example.com", da.Host)
	require.Equal(t, 8443, da.Port)

	again, err := fc.ResolveDERPAddr()
	require.NoError(t, err)
	require.Equal(t, addr, again)
}

// TestExampleConfigVPNIsResolvable 守护示例里的 VPN 配置本身可用：示例给出的
// 默认值不会与运行期的推导规则漂移。
//
// enabled 在示例里是 false（内嵌 DERP 会把该服务端变成节点组网的中继，运维应当
// 自己打开它——见 ExampleConfig 的注释），而 DERP 地址就由示例的 domain 与
// listen 推导，因此"照抄示例后只把 enabled 改成 true"必须能直接启动。
func TestExampleConfigVPNIsResolvable(t *testing.T) {
	fc := ExampleConfig()
	require.False(t, fc.Server.VPN.Enabled, "the example must not enable the relay by default")
	fc.Server.VPN.Enabled = true
	addr, err := fc.ResolveDERPAddr()
	require.NoError(t, err)
	require.Equal(t, "your-domain.com:443", addr)
}
