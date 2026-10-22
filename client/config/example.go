package config

import (
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/shaper"
)

// ExampleConfig 是完整模式配置示例；返回原样结构，由调用方决定序列化方式。
func ExampleConfig() ClientConfig {
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
