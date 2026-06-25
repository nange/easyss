package nextproxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

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
	if u.Scheme != "socks5" {
		return nil, fmt.Errorf("unsupported next proxy scheme %q", u.Scheme)
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

// AddDomain adds a domain to the routing list (thread-safe).
// If the domain is already present, it returns immediately without acquiring the write lock.
func (np *NextProxy) AddDomain(domain string) {
	if np == nil {
		return
	}

	np.mu.RLock()
	_, exists := np.domains[domain]
	np.mu.RUnlock()
	if exists {
		return
	}

	np.mu.Lock()
	np.domains[domain] = struct{}{}
	np.mu.Unlock()
}

func (np *NextProxy) Dial(network, addr string) (net.Conn, error) {
	return np.DialContext(context.Background(), network, addr)
}

func (np *NextProxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return np.dialSOCKS5Context(ctx, network, addr)
}

func (np *NextProxy) dialSOCKS5Context(ctx context.Context, network, addr string) (net.Conn, error) {
	username := ""
	password := ""
	if np.url.User != nil {
		username = np.url.User.Username()
		password, _ = np.url.User.Password()
		log.Info("[NEXTPROXY] connecting via SOCKS5 proxy", "addr", np.url.Host, "network", network, "target", addr)
	} else {
		log.Debug("[NEXTPROXY] connecting via SOCKS5 proxy", "addr", np.url.Host, "network", network, "target", addr)
	}

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		c, err := socks5.NewClient(np.url.Host, username, password, 10, 10)
		if err != nil {
			ch <- result{nil, err}
			return
		}

		conn, err := c.Dial(network, addr)
		if err != nil {
			ch <- result{nil, err}
			return
		}

		// Clear the deadline set during SOCKS5 negotiation. The socks5 library
		// sets SetDeadline(now + TCPTimeout) in Negotiate() for the handshake
		// but never clears it, which would cause the connection to time out
		// after 10 seconds during data transfer.
		_ = conn.SetDeadline(time.Time{})

		ch <- result{conn, nil}
	}()

	select {
	case <-ctx.Done():
		// The dial goroutine is still running and will complete eventually.
		// We can't cancel the underlying TCP dial, but we abandon it.
		return nil, fmt.Errorf("socks5 dial cancelled: %w", ctx.Err())
	case res := <-ch:
		return res.conn, res.err
	}
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
