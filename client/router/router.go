package router

import (
	"bytes"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/nange/easyss/v3/assets"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"github.com/oschwald/geoip2-golang"
)

type HostRule int

const (
	HostRuleProxy HostRule = iota
	HostRuleDirect
	HostRuleBlock
)

type ProxyRule int

const (
	ProxyRuleAuto        ProxyRule = 1
	ProxyRuleReverseAuto ProxyRule = 2
	ProxyRuleProxy       ProxyRule = 3
	ProxyRuleDirect      ProxyRule = 4
	ProxyRuleAutoBlock   ProxyRule = 5
)

func ParseProxyRule(s string) ProxyRule {
	switch s {
	case "auto":
		return ProxyRuleAuto
	case "reverse_auto":
		return ProxyRuleReverseAuto
	case "proxy":
		return ProxyRuleProxy
	case "direct":
		return ProxyRuleDirect
	case "auto_block":
		return ProxyRuleAutoBlock
	default:
		return ProxyRuleAuto
	}
}

type IPV6Rule int

const (
	IPV6RuleEnable IPV6Rule = iota
	IPV6RuleAuto
	IPV6RuleDisable
)

func ParseIPV6Rule(s string) IPV6Rule {
	switch s {
	case "enable":
		return IPV6RuleEnable
	case "auto":
		return IPV6RuleAuto
	default:
		return IPV6RuleDisable
	}
}

type GeoSite struct {
	domain       map[string]struct{}
	fullDomain   map[string]struct{}
	regexpDomain []*regexp.Regexp
}

func NewGeoSite(data []byte) *GeoSite {
	gs := &GeoSite{
		domain:     make(map[string]struct{}),
		fullDomain: make(map[string]struct{}),
	}

	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("full:")) {
			gs.fullDomain[string(line[5:])] = struct{}{}
			continue
		}
		if bytes.HasPrefix(line, []byte("regexp:")) {
			re, err := regexp.Compile(string(line[7:]))
			if err != nil {
				continue
			}
			gs.regexpDomain = append(gs.regexpDomain, re)
			continue
		}
		gs.domain[string(line)] = struct{}{}
	}

	return gs
}

func (gs *GeoSite) SimpleMatch(domain string, matchSub bool) bool {
	if _, ok := gs.fullDomain[domain]; ok {
		return true
	}
	if _, ok := gs.domain[domain]; ok {
		return true
	}
	if matchSub {
		subs := subDomains(domain)
		for _, sub := range subs {
			if _, ok := gs.domain[sub]; ok {
				return true
			}
		}
	}
	return false
}

func (gs *GeoSite) FullMatch(domain string) bool {
	if gs.SimpleMatch(domain, true) {
		return true
	}
	for _, re := range gs.regexpDomain {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

func subDomains(domain string) []string {
	if domain == "" {
		return nil
	}
	subs := make([]string, 0, 8)
	i := strings.Index(domain, ".")
	for i > 0 {
		domain = domain[i+1:]
		subs = append(subs, domain)
		i = strings.Index(domain, ".")
	}
	if len(subs) > 1 {
		return subs[:len(subs)-1]
	}
	return nil
}

type Config struct {
	ProxyRule         ProxyRule
	IPV6Rule          IPV6Rule
	DirectIPsFile     string
	DirectDomainsFile string
	DirectDNSServer   string
	IPV6NetWorking    bool
	ServerIPV6        string
}

type Router struct {
	cfg Config

	proxyRule atomic.Int32
	ipv6Rule  atomic.Int32

	geoIPDB       *geoip2.Reader
	geoSiteDirect *GeoSite
	geoSiteBlock  *GeoSite

	customMu            sync.RWMutex
	customDirectIPs     map[string]struct{}
	customDirectCIDRIPs []*net.IPNet
	customDirectDomains map[string]struct{}
}

func New(cfg Config) (*Router, error) {
	db, err := geoip2.FromBytes(assets.GeoIPCNPrivate)
	if err != nil {
		return nil, err
	}

	r := &Router{
		cfg:           cfg,
		geoIPDB:       db,
		geoSiteDirect: NewGeoSite(assets.GeoSiteDirect),
		geoSiteBlock:  NewGeoSite(assets.GeoSiteBlock),
	}
	r.proxyRule.Store(int32(cfg.ProxyRule))
	r.ipv6Rule.Store(int32(cfg.IPV6Rule))

	if err := r.loadCustomIPDomains(); err != nil {
		log.Error("[ROUTER] load custom ip/domains", "err", err)
	}

	return r, nil
}

func (r *Router) loadCustomIPDomains() error {
	r.customDirectIPs = make(map[string]struct{})
	r.customDirectDomains = make(map[string]struct{})

	if r.cfg.DirectIPsFile != "" {
		directIPs, err := util.ReadFileLinesMap(r.cfg.DirectIPsFile)
		if err != nil {
			return err
		}
		for k := range directIPs {
			_, ipnet, err := net.ParseCIDR(k)
			if err != nil {
				r.customDirectIPs[k] = struct{}{}
				continue
			}
			if ipnet != nil {
				r.customDirectCIDRIPs = append(r.customDirectCIDRIPs, ipnet)
			}
		}
	}

	if r.cfg.DirectDomainsFile != "" {
		directDomains, err := util.ReadFileLinesMap(r.cfg.DirectDomainsFile)
		if err != nil {
			return err
		}
		for domain := range directDomains {
			r.customDirectDomains[domain] = struct{}{}
		}
	}

	return nil
}

func (r *Router) MatchHostRule(host string) HostRule {
	rule := ProxyRule(r.proxyRule.Load())
	if rule == ProxyRuleDirect || r.isLANHost(host) {
		return HostRuleDirect
	}
	if rule == ProxyRuleProxy {
		return HostRuleProxy
	}
	if r.hostMatchCustomDirect(host) {
		return HostRuleDirect
	}
	if rule == ProxyRuleAutoBlock && !util.IsIP(host) {
		if r.geoSiteDirect.SimpleMatch(host, false) {
			return HostRuleDirect
		}
		if r.geoSiteBlock.SimpleMatch(host, true) {
			return HostRuleBlock
		}
	}
	if rule == ProxyRuleReverseAuto && !r.hostAtCN(host) {
		return HostRuleDirect
	}
	if r.hostAtCN(host) {
		return HostRuleDirect
	}
	return HostRuleProxy
}

func (r *Router) hostMatchCustomDirect(host string) bool {
	r.customMu.RLock()
	defer r.customMu.RUnlock()

	if util.IsIP(host) {
		if _, ok := r.customDirectIPs[host]; ok {
			return true
		}
		for _, cidr := range r.customDirectCIDRIPs {
			if cidr.Contains(net.ParseIP(host)) {
				return true
			}
		}
	} else {
		if _, ok := r.customDirectDomains[host]; ok {
			return true
		}
		subs := subDomains(host)
		for _, sub := range subs {
			if _, ok := r.customDirectDomains[sub]; ok {
				return true
			}
		}
	}
	return false
}

func (r *Router) hostAtCN(host string) bool {
	if host == "" {
		return false
	}
	if util.IsIP(host) {
		return r.ipAtCN(host)
	}
	if strings.HasSuffix(host, ".cn") {
		return true
	}
	return r.geoSiteDirect.FullMatch(host)
}

func (r *Router) ipAtCN(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}
	country, err := r.geoIPDB.Country(_ip)
	if err != nil {
		return false
	}
	return country.Country.IsoCode == "CN"
}

func (r *Router) isLANHost(host string) bool {
	if host == "localhost" {
		return true
	}
	return util.IsLANIP(host)
}

func (r *Router) ShouldIPV6Disable() bool {
	switch IPV6Rule(r.ipv6Rule.Load()) {
	case IPV6RuleEnable:
		return false
	case IPV6RuleAuto:
		if r.cfg.IPV6NetWorking && r.cfg.ServerIPV6 != "" {
			return false
		}
	}
	return true
}

func (r *Router) ProxyRule() ProxyRule {
	return ProxyRule(r.proxyRule.Load())
}

func (r *Router) SetProxyRule(rule ProxyRule) {
	r.proxyRule.Store(int32(rule))
}

func (r *Router) SetIPV6Info(networking bool, serverIPV6 string) {
	r.cfg.IPV6NetWorking = networking
	r.cfg.ServerIPV6 = serverIPV6
}

func (r *Router) ServerIPV6() string {
	return r.cfg.ServerIPV6
}

