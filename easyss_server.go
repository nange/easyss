package easyss

import (
	"crypto/tls"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/nange/easyss/v2/httptunnel"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util"
)

type EasyServer struct {
	config           *ServerConfig
	mu               sync.Mutex
	ln               net.Listener
	httpTunnelServer *httptunnel.Server
	tlsConfig        *tls.Config

	nextProxyIPs     map[string]struct{}
	nextProxyCIDRIPs []*net.IPNet
	nextProxyDomains map[string]struct{}

	// only used for testing
	disableValidateAddr bool
}

func NewServer(config *ServerConfig) (*EasyServer, error) {
	es := &EasyServer{config: config}

	if u := es.NextProxyURL(); u != nil {
		log.Info("[EASYSS_SERVER] next proxy is enabled",
			"next_proxy_url", u.String(),
			"enable_next_proxy_udp", es.EnableNextProxyUDP(),
			"enable_next_proxy_all_host", es.EnableNextProxyALLHost())
		if err := es.loadNextProxyIPDomains(); err != nil {
			return nil, err
		}
		es.printNextProxyInfo()
	}

	return es, nil
}

func (es *EasyServer) loadNextProxyIPDomains() error {
	es.nextProxyIPs = make(map[string]struct{})
	es.nextProxyDomains = make(map[string]struct{})

	nextIPs, err := util.ReadFileLinesMap(es.config.NextProxyIPsFile)
	if err != nil {
		return err
	}

	if len(nextIPs) > 0 {
		log.Info("[EASYSS_SERVER] load next proxy ips success", "len", len(nextIPs))
		for k := range nextIPs {
			_, ipnet, err := net.ParseCIDR(k)
			if err != nil {
				continue
			}
			if ipnet != nil {
				es.nextProxyCIDRIPs = append(es.nextProxyCIDRIPs, ipnet)
				delete(nextIPs, k)
			}
		}
		es.nextProxyIPs = nextIPs
	}

	nextDomains, err := util.ReadFileLinesMap(es.config.NextProxyDomainsFile)
	if err != nil {
		return err
	}
	if len(nextDomains) > 0 {
		log.Info("[EASYSS_SERVER] load next proxy domains success", "len", len(nextDomains))
		es.nextProxyDomains = nextDomains
		// not only proxy the domains but also the ips of domains
		for domain := range nextDomains {
			ips, err := util.LookupIPV4From(DefaultDNSServer, domain)
			if err != nil {
				log.Warn("[EASYSS_SERVER] lookup ip for", "domain", domain, "err", err)
				continue
			}
			for _, ip := range ips {
				es.nextProxyIPs[ip.String()] = struct{}{}
			}
		}
	}

	return nil
}

func (es *EasyServer) printNextProxyInfo() {
	keys := make([]string, 0, len(es.nextProxyDomains))

	for k := range es.nextProxyDomains {
		keys = append(keys, k)
	}
	log.Info("[EASYSS_SERVER] next proxy domains", "domains", keys)

	keys = keys[:0]
	for k := range es.nextProxyIPs {
		keys = append(keys, k)
	}
	for _, v := range es.nextProxyCIDRIPs {
		keys = append(keys, v.String())
	}
	log.Info("[EASYSS_SERVER] next proxy ips", "ips", keys)
}

func (es *EasyServer) Server() string {
	return es.config.Server
}

func (es *EasyServer) ListenAddr() string {
	addr := ":" + strconv.Itoa(es.ServerPort())
	return addr
}

func (es *EasyServer) ListenHTTPTunnelAddr() string {
	addr := ":" + strconv.Itoa(es.HTTPInboundPort())
	return addr
}

func (es *EasyServer) DisableUTLS() bool {
	return es.config.DisableUTLS
}

func (es *EasyServer) DisableTLS() bool {
	return es.config.DisableTLS
}

func (es *EasyServer) ServerPort() int {
	return es.config.ServerPort
}

func (es *EasyServer) Password() string {
	return es.config.Password
}

func (es *EasyServer) Timeout() time.Duration {
	return time.Duration(es.config.Timeout) * time.Second
}

func (es *EasyServer) CertPath() string {
	return es.config.CertPath
}

func (es *EasyServer) KeyPath() string {
	return es.config.KeyPath
}

func (es *EasyServer) EnabledHTTPInbound() bool {
	return es.config.EnableHTTPInbound
}

func (es *EasyServer) HTTPInboundPort() int {
	return es.config.HTTPInboundPort
}

func (es *EasyServer) NextProxyURL() *url.URL {
	if es.config.NextProxyURL == "" {
		return nil
	}
	u, _ := url.Parse(es.config.NextProxyURL)
	return u
}

func (es *EasyServer) EnableNextProxyUDP() bool {
	return es.config.EnableNextProxyUDP
}

func (es *EasyServer) EnableNextProxyALLHost() bool {
	return es.config.EnableNextProxyALLHost
}

func (es *EasyServer) NextProxyDomainsFile() string {
	return es.config.NextProxyDomainsFile
}

func (es *EasyServer) NextProxyIPsFile() string {
	return es.config.NextProxyIPsFile
}

func (es *EasyServer) Close() (err error) {
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.ln != nil {
		err = es.ln.Close()
	}
	if es.httpTunnelServer != nil {
		err = es.httpTunnelServer.Close()
	}
	return
}
