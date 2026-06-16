package nextproxy

import (
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/nange/easyss/v3/log"
	"github.com/txthinking/socks5"
)

type NextProxy struct {
	url       *url.URL
	enableUDP bool
	allHost   bool

	mu      sync.RWMutex //nolint:unused
	ips     map[string]struct{}
	cidrIPs []*net.IPNet
	domains map[string]struct{}
}

func New(proxyURL string, enableUDP, allHost bool) (*NextProxy, error) {
	if proxyURL == "" {
		return nil, nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	np := &NextProxy{
		url:       u,
		enableUDP: enableUDP,
		allHost:   allHost,
		ips:       make(map[string]struct{}),
		domains:   make(map[string]struct{}),
	}

	return np, nil
}

func (np *NextProxy) LoadIPDomainFiles(ipsFile, domainsFile string) error {
	if np == nil {
		return nil
	}

	if ipsFile != "" {
		ips, err := readFileLinesMap(ipsFile)
		if err != nil {
			return err
		}
		for k := range ips {
			_, ipnet, err2 := net.ParseCIDR(k)
			if err2 != nil {
				np.ips[k] = struct{}{}
				continue
			}
			if ipnet != nil {
				np.cidrIPs = append(np.cidrIPs, ipnet)
			}
		}
		log.Info("[NEXTPROXY] loaded IP rules", "file", ipsFile, "ips", len(np.ips), "cidrs", len(np.cidrIPs))
	}

	if domainsFile != "" {
		domains, err := readFileLinesMap(domainsFile)
		if err != nil {
			return err
		}
		for domain := range domains {
			np.domains[domain] = struct{}{}
		}
		log.Info("[NEXTPROXY] loaded domain rules", "file", domainsFile, "count", len(np.domains))
	}

	return nil
}

func (np *NextProxy) ShouldProxy(host string) bool {
	if np == nil {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if np.allHost {
		return true
	}

	if _, ok := np.ips[host]; ok {
		return true
	}
	for _, cidr := range np.cidrIPs {
		if cidr.Contains(net.ParseIP(host)) {
			return true
		}
	}
	if _, ok := np.domains[host]; ok {
		return true
	}
	return false
}

func (np *NextProxy) Dial(network, addr string) (net.Conn, error) {
	if np.url.Scheme == "socks5" {
		return np.dialSOCKS5(network, addr)
	}
	return net.Dial(network, addr)
}

func (np *NextProxy) dialSOCKS5(network, addr string) (net.Conn, error) {
	username := ""
	password := ""
	if np.url.User != nil {
		username = np.url.User.Username()
		password, _ = np.url.User.Password()
		log.Info("[NEXTPROXY] connecting via SOCKS5 proxy", "addr", np.url.Host, "network", network, "target", addr)
	} else {
		log.Debug("[NEXTPROXY] connecting via SOCKS5 proxy", "addr", np.url.Host, "network", network, "target", addr)
	}

	c, err := socks5.NewClient(np.url.Host, username, password, 10, 10)
	if err != nil {
		return nil, err
	}

	return c.Dial(network, addr)
}

func (np *NextProxy) DialUDP(addr string) (*net.UDPConn, error) {
	return net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(addr), Port: 0})
}

func (np *NextProxy) URL() *url.URL {
	if np == nil {
		return nil
	}
	return np.url
}

func (np *NextProxy) EnableUDP() bool {
	if np == nil {
		return false
	}
	return np.enableUDP
}

func readFileLinesMap(filePath string) (map[string]struct{}, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	result := make(map[string]struct{})
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result[line] = struct{}{}
	}
	return result, nil
}
