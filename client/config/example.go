package config

import (
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/shaper"
)

// ExampleConfig 是完整模式配置示例；返回原样结构，由调用方决定序列化方式。
func ExampleConfig() ClientConfig {
	// vpn.relay_only 缺省为 true：示例显式写出来，让"默认值是 true"这件事在 JSON 里可见。
	relayOnly := true
	return ClientConfig{
		ConfigVersion: 3,
		Servers: []*ServerProfile{{
			Host:     "your-domain.com",
			Port:     config.DefaultServerPort,
			Password: "your-password",
			Method:   config.DefaultMethod,
			SNI:      "",
			CAPath:   "",
			Default:  true,
		}},
		// 示例不走 applyDefaults，http_port 按同一规则显式给出。
		Local: LocalConfig{
			SocksPort:        config.DefaultSocksPort,
			HTTPPort:         config.DefaultSocksPort + config.DefaultHTTPPortOffset,
			BindAll:          false,
			DisableSysProxy:  false,
			EnableForwardDNS: false,
			EnableTun2socks:  false,
			EnableQUIC:       false,
			TunMTU:           config.DefaultTunMTU,
		},
		Routing: RoutingConfig{
			ProxyRule:  config.DefaultProxyRule,
			IPV6Rule:   config.DefaultIPV6Rule,
			DirectFile: "",
			ProxyFile:  "",
		},
		// VPN 组网默认关闭：示例里打开会连带一个填了占位符的 peers，反而让"拿示例直接跑"
		// 失败。这里只把字段形状展示出来，用户填空后改成 true 即可。
		VPN: VPNConfig{
			Enabled:   false,
			RelayOnly: &relayOnly,
			// peer_port 留空表示按 socks_port + 2000 派生（这里即 4080 → 6080）。
			PeerPort: config.DefaultVPNPeerPort,
			// DERP 位置没有配置项：它由 servers[] 里带 "derp": true 标记的条目共同派生
			// （一条都没有时取当前连接的服务端）。同一 region 最多 3 台，推荐 1-2 台。
			Peers: []VPNPeer{{
				HostName: "b",
				Address:  "tc...(copy the full address printed by peer b's vpn startup log)",
			}},
			AllowClients: []string{"nodekey:...(optional allowlist; see vpn.allow_clients)"},
		},
		Transport: TransportConfig{
			Protocol:          config.DefaultProtocol,
			ConnCountMax:      config.DefaultConnCountMax,
			StreamThreshold:   config.DefaultStreamThreshold,
			PrioritySlotRatio: config.DefaultPrioritySlotRatio,
			ConnMaxBytes:      config.DefaultConnMaxBytes,
		},
		Shaper: shaper.Config{
			BatchWindowMS: config.DefaultBatchWindowMS,
			BudgetRatio:   config.DefaultCoverBudgetRatio,
			BudgetCap:     config.DefaultCoverBudgetCap,
		},
		Log: log.Config{
			Level:    config.DefaultLogLevel,
			FilePath: "easyss.log",
		},
		Timeout:      config.DefaultTimeout,
		AuthUsername: "",
		AuthPassword: "",
		PprofEnabled: false,
	}
}

// ExampleSimpleConfig 是简化模式配置示例。
func ExampleSimpleConfig() config.SimpleConfig {
	return config.SimpleConfig{
		Server:        "your-domain.com",
		ServerPort:    config.DefaultServerPort,
		Password:      "your-password",
		Method:        config.DefaultMethod,
		LocalPort:     config.DefaultSocksPort,
		ProxyRule:     config.DefaultProxyRule,
		Timeout:       config.DefaultTimeout,
		BindAll:       false,
		OutboundProto: "native",
		DirectFile:    "",
		ProxyFile:     "",
		LogLevel:      config.DefaultLogLevel,
		LogFilePath:   "easyss.log",
	}
}
