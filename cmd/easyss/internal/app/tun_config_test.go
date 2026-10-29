package app

import (
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/router"
)

// TestTunConfigSocksAddrFollowsBindAll 固定 TUN 引擎拿到的本地 SOCKS5 端点：
// 它必须与入口监听同源（见 util.Socks5URI）。bind_all 时入口监听 [::]，引擎却
// 拨 127.0.0.1 的话，在只接受 IPv6 回环的环境里 TUN 设备建得起来、引擎却连不上
// 本地 SOCKS5——表现为开启系统全局流量后全部流量中断。
func TestTunConfigSocksAddrFollowsBindAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		bindAll bool
		want    string
	}{
		{
			name: "loopback only",
			want: "socks5://127.0.0.1:4080",
		},
		{
			name:    "bind all",
			bindAll: true,
			want:    "socks5://[::1]:4080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New(&clientconfig.ClientConfig{Local: clientconfig.LocalConfig{
				SocksPort: 4080,
				BindAll:   tt.bindAll,
			}}, "")

			if got := a.sess.tunConfig().Socks5Addr; got != tt.want {
				t.Fatalf("tunConfig().Socks5Addr = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestTunServerIPV6MatchesTheIPV6Policy 固定"TUN 接管 IPv6 ⇒ 代理层接受 IPv6 目标"：
// 判据与 ShouldIPV6Disable 完全一致。接管了却在策略门拒绝时，连接会在 TUN 里被接受、
// 再被拒绝，TLS 握手永远等不到回应，应用不会回退到可用的 IPv4 地址。
func TestTunServerIPV6MatchesTheIPV6Policy(t *testing.T) {
	t.Parallel()

	const serverIPV6 = "2001:db8::1"
	tests := []struct {
		name       string
		rule       router.IPV6Rule
		networking bool
		server     string
		want       string
	}{
		{
			name:   "auto 且本机没有 IPv6 出口时不接管",
			rule:   router.IPV6RuleAuto,
			server: serverIPV6,
		},
		{
			name:       "auto 且本机有 IPv6 出口时接管",
			rule:       router.IPV6RuleAuto,
			networking: true,
			server:     serverIPV6,
			want:       serverIPV6,
		},
		{
			name:       "auto 且服务端没有 IPv6 时不接管",
			rule:       router.IPV6RuleAuto,
			networking: true,
		},
		{
			name:   "enable 在本机没有 IPv6 出口时也强制接管",
			rule:   router.IPV6RuleEnable,
			server: serverIPV6,
			want:   serverIPV6,
		},
		{
			name: "enable 但服务端没有 IPv6 时不接管",
			rule: router.IPV6RuleEnable,
		},
		{
			name:       "disable 时一律不接管：策略门会拒绝 IPv6 目标",
			rule:       router.IPV6RuleDisable,
			networking: true,
			server:     serverIPV6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rt, err := router.New(router.Config{IPV6Rule: tt.rule})
			if err != nil {
				t.Fatalf("router.New: %v", err)
			}
			rt.SetIPV6Info(tt.networking, tt.server)

			if got := tunServerIPV6(rt); got != tt.want {
				t.Fatalf("tunServerIPV6() = %q, want %q", got, tt.want)
			}
		})
	}

	if got := tunServerIPV6(nil); got != "" {
		t.Fatalf("tunServerIPV6(nil) = %q, want empty", got)
	}
}
