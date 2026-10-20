package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateTLS 守住配置加载阶段的校验：证书文件必须成对、ACME 模式下 host 必填、
// IP-only 只接受公网 IPv4。漏到运行期只会表现为"进程起不来"，或只配 cert_path 时静默改走 ACME。
func TestValidateTLS(t *testing.T) {
	t.Run("域名与 ACME 模式", func(t *testing.T) {
		cases := []struct {
			name   string
			server ServerConfig
			want   string
		}{
			{"普通域名", ServerConfig{Host: "example.com"}, ""},
			{"公网 IPv4", ServerConfig{Host: "1.2.3.4"}, ""},
			{"域名与手工证书并存时手工证书优先", ServerConfig{Host: "example.com", CertPath: "c.pem", KeyPath: "k.pem"}, ""},
			{"手工证书可以没有 host", ServerConfig{CertPath: "c.pem", KeyPath: "k.pem"}, ""},
			{"空 host 且无手工证书", ServerConfig{}, "server.host is required"},
			{"host 不得包含端口", ServerConfig{Host: "example.com:443"}, "must not include a port"},
			{"IPv4 host 不得包含端口", ServerConfig{Host: "1.2.3.4:443"}, "must not include a port"},
			// host 的形态约束与取证模式无关：手工证书模式下它只进日志，
			// 但同样不允许把端口写进来。
			{"手工证书下 host 也不得包含端口", ServerConfig{Host: "example.com:443", CertPath: "c.pem", KeyPath: "k.pem"}, "must not include a port"},
			{"只配 cert_path", ServerConfig{Host: "example.com", CertPath: "c.pem"}, "must be set together"},
			{"只配 key_path", ServerConfig{Host: "example.com", KeyPath: "k.pem"}, "must be set together"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fc := &FileConfig{Server: tc.server}
				err := fc.validateTLS()
				if tc.want == "" {
					require.NoError(t, err)
					return
				}
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.want)
			})
		}
	})

	t.Run("不可公网签发的 IP 字面量", func(t *testing.T) {
		// 全部落在 util.IsLANIP 覆盖的范围内：Let's Encrypt 验证时会连接该地址的
		// 443 并拒绝非公网地址，Boulder 侧还有 reserved-IP 兜底，因此这些配置注定
		// 申请失败——必须在配置加载阶段就说清楚出路，而不是等一轮 ACME 往返。
		for _, host := range []string{
			"10.0.0.1",     // RFC1918
			"172.16.0.1",   // RFC1918
			"192.168.1.10", // RFC1918
			"100.64.0.1",   // CGNAT
			"127.0.0.1",    // 环回
			"169.254.1.1",  // 链路本地
			"0.0.0.0",      // 未指定
			"192.0.0.1",    // IETF 协议分配段
			"198.18.0.1",   // 基准测试段
			"192.0.2.1",    // TEST-NET-1
			"198.51.100.1", // TEST-NET-2
			"203.0.113.1",  // TEST-NET-3
			"224.0.0.1",    // 多播
			"255.255.255.255",
		} {
			t.Run(host, func(t *testing.T) {
				fc := &FileConfig{Server: ServerConfig{Host: host}}
				err := fc.validateTLS()
				require.Error(t, err)
				require.Contains(t, err.Error(), "public")
				require.Contains(t, err.Error(), "server.cert_path")
			})
		}
	})

	t.Run("不是纯 IPv4 字面量的 IP 写法", func(t *testing.T) {
		// 客户端用 https://<host>:<port> 与 <host>:<port> 拼服务端地址，
		// 这三种写法在那里都无法表达（IPv6 会以 "too many colons" 在 net.Dial
		// 失败，那个症状看起来与证书无关），因此在配置加载阶段就拒绝。
		for _, host := range []string{"2001:db8::1", "[2001:db8::1]", "::ffff:1.2.3.4", "[1.2.3.4]"} {
			t.Run(host, func(t *testing.T) {
				fc := &FileConfig{Server: ServerConfig{Host: host}}
				err := fc.validateTLS()
				require.Error(t, err)
				require.Contains(t, err.Error(), "IPv4")
			})
		}
	})

	t.Run("手工证书模式下 IP 形态不参与校验", func(t *testing.T) {
		// 自签证书部署在 NAT 后面是常见形态：那时 host 不参与取证，写私有地址
		// 只是给日志看，不该被 ACME 的公网性要求挡住。
		fc := &FileConfig{Server: ServerConfig{Host: "192.168.1.10", CertPath: "c.pem", KeyPath: "k.pem"}}
		require.NoError(t, fc.validateTLS())
	})
}

// TestLoadConfigValidatesTLS 固定校验发生在配置加载阶段（LoadConfig），且不联网：
// 一份注定签不下证书的 IP-only 配置必须在进程启动前就被拒绝。
func TestLoadConfigValidatesTLS(t *testing.T) {
	t.Run("公网 IPv4 通过", func(t *testing.T) {
		fc, err := LoadConfig(writeConfig(t, `{"server":{"host":"1.2.3.4","port":443,"password":"p"}}`))
		require.NoError(t, err)
		require.Equal(t, "1.2.3.4", fc.Server.Host)
	})

	t.Run("私有地址启动失败", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{"server":{"host":"192.168.1.10","port":443,"password":"p"}}`))
		require.ErrorContains(t, err, "private or reserved")
	})

	t.Run("IPv6 字面量启动失败", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{"server":{"host":"2001:db8::1","port":443,"password":"p"}}`))
		require.ErrorContains(t, err, "IPv4")
	})

	t.Run("证书只配一半启动失败", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{"server":{"port":443,"cert_path":"c.pem"}}`))
		require.ErrorContains(t, err, "must be set together")
	})

	t.Run("host 带端口启动失败", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{"server":{"host":"example.com:443","port":443,"password":"p"}}`))
		require.ErrorContains(t, err, "must not include a port")
	})

	t.Run("手工证书模式下 host 带端口同样失败", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `{"server":{"host":"example.com:443","port":443,"cert_path":"c.pem","key_path":"k.pem","password":"p"}}`))
		require.ErrorContains(t, err, "must not include a port")
	})
}

// TestACMESubjectIsIP 守住只看形态、不看能否签发：它决定是否显式请求短生命周期 profile，
// 公网性由 validateTLS 在更早的位置把关。
func TestACMESubjectIsIP(t *testing.T) {
	cases := []struct {
		name   string
		server ServerConfig
		want   bool
	}{
		{"域名", ServerConfig{Host: "example.com"}, false},
		{"公网 IPv4", ServerConfig{Host: "1.2.3.4"}, true},
		{"私有 IPv4 也是 IP 模式", ServerConfig{Host: "192.168.1.10"}, true},
		{"空 host", ServerConfig{}, false},
		{"IPv6", ServerConfig{Host: "2001:db8::1"}, false},
		{"IPv4-mapped", ServerConfig{Host: "::ffff:1.2.3.4"}, false},
		{"带方括号", ServerConfig{Host: "[1.2.3.4]"}, false},
		{"手工证书模式恒为 false", ServerConfig{Host: "1.2.3.4", CertPath: "c.pem", KeyPath: "k.pem"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FileConfig{Server: tc.server}
			require.Equal(t, tc.want, fc.ACMESubjectIsIP())
			require.Equal(t, tc.server.CertPath != "" && tc.server.KeyPath != "", fc.UsesManualCertificate())
		})
	}
}
