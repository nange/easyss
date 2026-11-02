package runner

import (
	"errors"
	"net"
	"strings"
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
)

// TestLocalProxyExposureWarning 固定"bind_all + 无鉴权"的判定：鉴权只在用户名与密码
// 同时非空时生效（与 SOCKS5 入口一致），只配一半同样是开放代理。
func TestLocalProxyExposureWarning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		bindAll    bool
		username   string
		password   string
		socksPort  int
		httpPort   int
		wantAddrs  []string
		wantNoWarn bool
	}{
		{
			name:       "默认只监听回环",
			socksPort:  1080,
			httpPort:   2080,
			wantNoWarn: true,
		},
		{
			name:       "bind_all 且已配置鉴权",
			bindAll:    true,
			username:   "user",
			password:   "pass",
			socksPort:  1080,
			httpPort:   2080,
			wantNoWarn: true,
		},
		{
			name:      "bind_all 且无鉴权",
			bindAll:   true,
			socksPort: 1080,
			httpPort:  2080,
			wantAddrs: []string{"socks5=[::]:1080", "http=[::]:2080"},
		},
		{
			name:      "只配用户名仍算无鉴权",
			bindAll:   true,
			username:  "user",
			socksPort: 1080,
			wantAddrs: []string{"socks5=[::]:1080"},
		},
		{
			name:      "只配密码仍算无鉴权",
			bindAll:   true,
			password:  "pass",
			socksPort: 1080,
			wantAddrs: []string{"socks5=[::]:1080"},
		},
		{
			name:       "bind_all 但没有任何本地入口",
			bindAll:    true,
			wantNoWarn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &clientconfig.ClientConfig{
				Local: clientconfig.LocalConfig{
					BindAll:   tt.bindAll,
					SocksPort: tt.socksPort,
					HTTPPort:  tt.httpPort,
				},
				AuthUsername: tt.username,
				AuthPassword: tt.password,
			}

			err := localProxyExposureWarning(cfg)
			if tt.wantNoWarn {
				if err != nil {
					t.Fatalf("localProxyExposureWarning = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrProxyExposedWithoutAuth) {
				t.Fatalf("localProxyExposureWarning = %v, want ErrProxyExposedWithoutAuth", err)
			}
			for _, addr := range tt.wantAddrs {
				if !strings.Contains(err.Error(), addr) {
					t.Errorf("warning %q is missing listener %q", err, addr)
				}
			}
		})
	}
}

// TestRunWarnsWhenBindAllWithoutAuth 守住接线：警告必须进入 Core.StartupWarn，否则
// 托盘拿不到、headless 也不会打日志。
func TestRunWarnsWhenBindAllWithoutAuth(t *testing.T) {
	t.Parallel()

	// bind_all 监听 [::]：平台没有 IPv6 通配监听时无法复现该配置。
	probe, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Skipf("wildcard ipv6 listen unavailable: %v", err)
	}
	_ = probe.Close()

	cfg := testConfig()
	cfg.Local.BindAll = true
	cfg.Local.HTTPPort = 0

	core := startRetrying(t, func() (*Core, error) {
		cfg.Local.SocksPort = freePort(t)
		return Run(cfg)
	})
	defer core.Stop()

	if !errors.Is(core.StartupWarn, ErrProxyExposedWithoutAuth) {
		t.Fatalf("StartupWarn = %v, want ErrProxyExposedWithoutAuth", core.StartupWarn)
	}
}
