//go:build !windows

package util

import "github.com/miekg/dns"

// sysDNSServersFromResolvConf parses the dns servers from a resolv.conf file,
// the path is parameterized for testing.
func sysDNSServersFromResolvConf(path string) ([]string, error) {
	cfg, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, err
	}
	return cfg.Servers, nil
}
