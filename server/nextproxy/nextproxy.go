package nextproxy

import (
	"net"
	"net/url"
	"sync"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"github.com/txthinking/socks5"
)

type NextProxy struct {
	url       *url.URL
	enableUDP bool
	allHost   bool

	mu      sync.RWMutex
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

func (np *NextProxy) LoadProxyFile(proxyFile string) error {
	if np == nil {
		return nil
	}

	if proxyFile == "" {
		return nil
	}

	entries, err := util.ReadFileLinesMap(proxyFile)
	if err != nil {
		return err
	}

	np.mu.Lock()
	defer np.mu.Unlock()

	for k := range entries {
		_, ipnet, err2 := net.ParseCIDR(k)
		if err2 == nil && ipnet != nil {
			np.cidrIPs = append(np.cidrIPs, ipnet)
			continue
		}
		if util.IsIP(k) {
			np.ips[k] = struct{}{}
			continue
		}
		np.domains[k] = struct{}{}
	}
	log.Info("[NEXTPROXY] loaded proxy file", "file", proxyFile, "ips", len(np.ips), "cidrs", len(np.cidrIPs), "domains", len(np.domains))

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

	np.mu.RLock()
	defer np.mu.RUnlock()

	if util.IsIP(host) {
		if _, ok := np.ips[host]; ok {
			return true
		}
		for _, cidr := range np.cidrIPs {
			if cidr.Contains(net.ParseIP(host)) {
				return true
			}
		}
	} else {
		if _, ok := np.domains[host]; ok {
			return true
		}
		for _, sub := range util.SubDomains(host) {
			if _, ok := np.domains[sub]; ok {
				return true
			}
		}
	}
	return false
}

// IsCustomDomain checks whether a domain is in the custom domain list,
// including subdomain matching.
func (np *NextProxy) IsCustomDomain(domain string) bool {
	if np == nil {
		return false
	}

	np.mu.RLock()
	defer np.mu.RUnlock()

	if _, ok := np.domains[domain]; ok {
		return true
	}
	for _, sub := range util.SubDomains(domain) {
		if _, ok := np.domains[sub]; ok {
			return true
		}
	}
	return false
}

// AddIP adds an IP to the routing list (thread-safe).
// If the IP is already present, it returns immediately without acquiring the write lock.
func (np *NextProxy) AddIP(ip string) {
	if np == nil {
		return
	}

	np.mu.RLock()
	_, exists := np.ips[ip]
	np.mu.RUnlock()
	if exists {
		return
	}

	np.mu.Lock()
	np.ips[ip] = struct{}{}
	np.mu.Unlock()
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
