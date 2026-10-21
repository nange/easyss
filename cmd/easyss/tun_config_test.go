package main

import (
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
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
			a := newApp(&clientconfig.ClientConfig{Local: clientconfig.LocalConfig{
				SocksPort: 4080,
				BindAll:   tt.bindAll,
			}}, "")

			if got := a.sess.tunConfig().Socks5Addr; got != tt.want {
				t.Fatalf("tunConfig().Socks5Addr = %q, want %q", got, tt.want)
			}
		})
	}
}
