//go:build !windows

package util

import "github.com/miekg/dns"

// sysDNSServersFromResolvConf 从 resolv.conf 文件中解析 DNS 服务器，
// 路径参数化以便测试。
func sysDNSServersFromResolvConf(path string) ([]string, error) {
	cfg, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, err
	}
	return cfg.Servers, nil
}
