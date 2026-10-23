package config

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nange/easyss/v3/config"
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

// TestResolveDERPAddr 固定服务端 DERP 地址的唯一来源：host + port，推导不出来必须报错
// 而不是猜——猜错的中继地址会让每个节点都连不上；也没有"显式覆盖"的配置项。
func TestResolveDERPAddr(t *testing.T) {
	t.Run("从 host 与 port 推导", func(t *testing.T) {
		cases := []struct {
			name string
			port int
			want string
		}{
			{"port 显式给出", 443, "example.com:443"},
			{"port 非默认", 8443, "example.com:8443"},
			{"port 为零取默认 443", 0, "example.com:443"},
		}
		for _, tc := range cases {
			fc := &FileConfig{Server: ServerConfig{Host: "example.com", Port: tc.port}}
			got, err := fc.ResolveDERPAddr()
			require.NoError(t, err, tc.name)
			require.Equal(t, tc.want, got, tc.name)
		}
	})

	t.Run("推导失败时报出缺的是哪一项", func(t *testing.T) {
		fc := &FileConfig{Server: ServerConfig{Port: 443}}
		_, err := fc.ResolveDERPAddr()
		require.Error(t, err)
		require.Contains(t, err.Error(), "server.host")
	})
}

// TestLoadConfigWarnsOnRemovedDERPAddr 固定降级行为：残留的 server.vpn.derp_addr 被忽略、
// 不影响推导，但必须留下日志——那种配置启动成功而 VPN 一直连不上。
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

	t.Run("启用但 host 为空时启动失败", func(t *testing.T) {
		// host 既是 ACME 标识符也是 DERP 的对外主机，缺了它中继地址根本推导不出来。
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"port": 443, "vpn": {"enabled": true}}
		}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "server.host")
	})

	t.Run("未启用时不校验", func(t *testing.T) {
		// 对端地址不是合法的 tailcat 地址：VPN 校验若执行必然失败，未启用时必须放过。
		_, err := LoadConfig(writeConfig(t, `{
			"server": {"host": "example.com", "port": 443,
				"vpn": {"enabled": false, "peers": [{"host_name": "b", "address": "not-a-tailcat-address"}]}}
		}`))
		require.NoError(t, err)
	})
}

// TestLoadConfigValidatesVPNMesh 固定 server.vpn 的 mesh 校验矩阵：key/peers 成对、对端
// 不能是自己也不能重复、每个对端都要有经隧道出网的路径（内嵌 DERP 只服务回环来源）。
func TestLoadConfigValidatesVPNMesh(t *testing.T) {
	base := func(mesh string) string {
		return `{
			"server": {
				"listen": ":443", "domain": "a.example.com", "vpn": {"enabled": true` + mesh + `}
			}
		}`
	}

	t.Run("完整的 mesh 配置通过", func(t *testing.T) {
		// 2 个对端 = region 里 3 台中继，正好是 config.MaxVPNRelays 的上限。
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

	t.Run("中继总数超过上限时启动失败", func(t *testing.T) {
		// mesh 是全互联：列出 3 个对端意味着 region 里有 4 台中继，超过
		// config.MaxVPNRelays（3 台）。这种配置没有可工作的形态——节点侧同样
		// 最多只能声明 3 台中继，第 4 台进不了任何地址——所以必须在启动时报错。
		_, err := LoadConfig(writeConfig(t, base(`,
			"mesh_key": "shared-passphrase",
			"mesh_peers": [
				{"addr": "b.example.com:443", "proxy": "socks5://127.0.0.1:1081"},
				{"addr": "c.example.com:443", "proxy": "socks5://127.0.0.1:1082"},
				{"addr": "d.example.com:443", "proxy": "socks5://127.0.0.1:1083"}
			]`)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "mesh_peers")
		require.Contains(t, err.Error(), "4 relays in total")
		require.Contains(t, err.Error(), "at most 3 relays")
		require.Contains(t, err.Error(), "1-2")
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

// TestResolveDERPAddrIsUsableDownstream 守护推导结果本身是合法的 host:port：调用方要把它
// 交给 net.SplitHostPort 拆成 DERPMap 的 HostName 与 DERPPort（见 vpn.BuildRegion）。
func TestResolveDERPAddrIsUsableDownstream(t *testing.T) {
	fc := &FileConfig{Server: ServerConfig{Host: "example.com", Port: 8443}}
	addr, err := fc.ResolveDERPAddr()
	require.NoError(t, err)

	da, err := config.SplitDERPAddr(addr)
	require.NoError(t, err)
	require.Equal(t, "example.com", da.Host)
	require.Equal(t, 8443, da.Port)

	again, err := fc.ResolveDERPAddr()
	require.NoError(t, err)
	require.Equal(t, addr, again)
}

// TestExampleConfigVPNIsResolvable 守护"照抄示例、只把 enabled 改成 true 就能启动"：
// 示例的默认值不能与运行期的推导规则漂移。
func TestExampleConfigVPNIsResolvable(t *testing.T) {
	fc := ExampleConfig()
	require.False(t, fc.Server.VPN.Enabled, "the example must not enable the relay by default")
	fc.Server.VPN.Enabled = true
	addr, err := fc.ResolveDERPAddr()
	require.NoError(t, err)
	require.Equal(t, "your-domain.com:443", addr)
}
