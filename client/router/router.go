package router

import (
	"bytes"
	"fmt"
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

	lines := bytes.SplitSeq(data, []byte("\n"))
	for line := range lines {
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
		subs := util.SubDomains(domain)
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

type Config struct {
	ProxyRule       ProxyRule
	IPV6Rule        IPV6Rule
	DirectFile      string
	ProxyFile       string
	DirectDNSServer string
	IPV6NetWorking  bool
	ServerIPV6      string
}

type Router struct {
	cfg Config

	proxyRule atomic.Int32
	ipv6Rule  atomic.Int32

	// IPv6 可用性在构造之后（client.New）才解析、并在每个请求时读取，
	// 因此与上面的规则一样以原子方式存储，而不是放进 cfg——cfg 的字段会
	// 产生数据竞争。
	ipv6Networking atomic.Bool
	serverIPV6     atomic.Pointer[string]

	geoIPDB       *geoip2.Reader
	geoSiteDirect *GeoSite
	geoSiteBlock  *GeoSite

	customMu            sync.RWMutex
	customDirectIPs     map[string]struct{}
	customDirectCIDRIPs []*net.IPNet
	customDirectDomains map[string]struct{}
	customDirectRegexps []*regexp.Regexp
	customProxyIPs      map[string]struct{}
	customProxyCIDRIPs  []*net.IPNet
	customProxyDomains  map[string]struct{}
	customProxyRegexps  []*regexp.Regexp

	// customFileErr 记录加载自定义直连/代理规则文件时遇到的第一个失败。
	// 加载刻意设计为非致命（路由器仍保留内置规则），但该错误会作为启动警告
	// 暴露出来，让用户知道自己的自定义规则没有被应用。
	customFileErr error
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
	r.SetIPV6Info(cfg.IPV6NetWorking, cfg.ServerIPV6)

	if err := r.loadCustomIPDomains(); err != nil {
		r.customFileErr = fmt.Errorf("load custom rule file: %w", err)
		log.Error("[ROUTER] load custom ip/domains", "err", err)
	}

	return r, nil
}

// CustomFileError 返回加载自定义直连/代理规则文件时遇到的第一个失败，
// 两个文件都加载成功时返回 nil。
func (r *Router) CustomFileError() error {
	return r.customFileErr
}

func (r *Router) loadCustomIPDomains() error {
	r.customDirectIPs = make(map[string]struct{})
	r.customDirectDomains = make(map[string]struct{})
	r.customProxyIPs = make(map[string]struct{})
	r.customProxyDomains = make(map[string]struct{})

	if r.cfg.DirectFile != "" {
		entries, err := util.ReadFileLinesMap(r.cfg.DirectFile)
		if err != nil {
			return err
		}
		for k := range entries {
			if strings.HasPrefix(k, "regexp:") {
				re, err := regexp.Compile(k[7:])
				if err == nil {
					r.customDirectRegexps = append(r.customDirectRegexps, re)
				}
				continue
			}
			if strings.Contains(k, "*") {
				re, err := util.GlobToRegexp(k)
				if err == nil {
					r.customDirectRegexps = append(r.customDirectRegexps, re)
				}
				continue
			}
			_, ipnet, err := net.ParseCIDR(k)
			if err == nil && ipnet != nil {
				r.customDirectCIDRIPs = append(r.customDirectCIDRIPs, ipnet)
				continue
			}
			if util.IsIP(k) {
				r.customDirectIPs[k] = struct{}{}
				continue
			}
			r.customDirectDomains[k] = struct{}{}
		}
		log.Info("[ROUTER] loaded direct file",
			"file", r.cfg.DirectFile,
			"total", len(entries),
			"ips", len(r.customDirectIPs),
			"cidrs", len(r.customDirectCIDRIPs),
			"domains", len(r.customDirectDomains),
			"patterns", len(r.customDirectRegexps),
		)
	}

	if r.cfg.ProxyFile != "" {
		entries, err := util.ReadFileLinesMap(r.cfg.ProxyFile)
		if err != nil {
			return err
		}
		for k := range entries {
			if strings.HasPrefix(k, "regexp:") {
				re, err := regexp.Compile(k[7:])
				if err == nil {
					r.customProxyRegexps = append(r.customProxyRegexps, re)
				}
				continue
			}
			if strings.Contains(k, "*") {
				re, err := util.GlobToRegexp(k)
				if err == nil {
					r.customProxyRegexps = append(r.customProxyRegexps, re)
				}
				continue
			}
			_, ipnet, err := net.ParseCIDR(k)
			if err == nil && ipnet != nil {
				r.customProxyCIDRIPs = append(r.customProxyCIDRIPs, ipnet)
				continue
			}
			if util.IsIP(k) {
				r.customProxyIPs[k] = struct{}{}
				continue
			}
			r.customProxyDomains[k] = struct{}{}
		}
		log.Info("[ROUTER] loaded proxy file",
			"file", r.cfg.ProxyFile,
			"total", len(entries),
			"ips", len(r.customProxyIPs),
			"cidrs", len(r.customProxyCIDRIPs),
			"domains", len(r.customProxyDomains),
			"patterns", len(r.customProxyRegexps),
		)
	}

	return nil
}

// HostClassification 是针对目标主机的路由决策结果。
type HostClassification struct {
	// Rule 是要应用的路由规则。
	Rule HostRule
	// IPV6Rejected 表示 Rule 被 IPv6 策略门强制为 HostRuleBlock
	// （即 IPv6 被禁用时遇到字面 IPv6 目标），调用方可以据此返回
	// 协议特定的拒绝响应。
	IPV6Rejected bool
}

// ClassifyHost 解析 host 的路由决策：先过 IPv6 策略门，再应用
// 直连/代理/屏蔽规则。所有请求路径（SOCKS5、HTTP CONNECT、UDP、TUN ICMP）
// 共用它，因此任何路径都不会漏掉策略门，也不会以不同顺序执行这两项检查。
// nil 路由器把所有流量都分类为走代理，这正是未配置的测试服务器所期望的行为。
func (r *Router) ClassifyHost(host string) HostClassification {
	if r == nil {
		return HostClassification{Rule: HostRuleProxy}
	}
	if r.ShouldIPV6Disable() && util.IsIPV6(host) {
		return HostClassification{Rule: HostRuleBlock, IPV6Rejected: true}
	}
	return HostClassification{Rule: r.MatchHostRule(host)}
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
	if r.hostMatchCustomProxy(host) {
		return HostRuleProxy
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
	if rule != ProxyRuleReverseAuto && r.hostAtCN(host) {
		return HostRuleDirect
	}
	return HostRuleProxy
}

func (r *Router) hostMatchCustomDirect(host string) bool {
	r.customMu.RLock()
	defer r.customMu.RUnlock()

	if util.IsIP(host) {
		if _, ok := r.customDirectIPs[host]; ok {
			log.Info("[ROUTER] custom direct ip matched", "host", host)
			return true
		}
		for _, cidr := range r.customDirectCIDRIPs {
			if cidr.Contains(net.ParseIP(host)) {
				log.Info("[ROUTER] custom direct cidr matched", "host", host, "cidr", cidr.String())
				return true
			}
		}
	} else {
		if _, ok := r.customDirectDomains[host]; ok {
			log.Info("[ROUTER] custom direct domain matched", "host", host)
			return true
		}
		subs := util.SubDomains(host)
		for _, sub := range subs {
			if _, ok := r.customDirectDomains[sub]; ok {
				log.Info("[ROUTER] custom direct subdomain matched", "host", host, "subdomain", sub)
				return true
			}
		}
		for _, re := range r.customDirectRegexps {
			if re.MatchString(host) {
				log.Info("[ROUTER] custom direct regexp matched", "host", host, "pattern", re.String())
				return true
			}
		}
	}
	return false
}

func (r *Router) hostMatchCustomProxy(host string) bool {
	r.customMu.RLock()
	defer r.customMu.RUnlock()

	if util.IsIP(host) {
		if _, ok := r.customProxyIPs[host]; ok {
			log.Info("[ROUTER] custom proxy ip matched", "host", host)
			return true
		}
		for _, cidr := range r.customProxyCIDRIPs {
			if cidr.Contains(net.ParseIP(host)) {
				log.Info("[ROUTER] custom proxy cidr matched", "host", host, "cidr", cidr.String())
				return true
			}
		}
	} else {
		if _, ok := r.customProxyDomains[host]; ok {
			log.Info("[ROUTER] custom proxy domain matched", "host", host)
			return true
		}
		subs := util.SubDomains(host)
		for _, sub := range subs {
			if _, ok := r.customProxyDomains[sub]; ok {
				log.Info("[ROUTER] custom proxy subdomain matched", "host", host, "subdomain", sub)
				return true
			}
		}
		for _, re := range r.customProxyRegexps {
			if re.MatchString(host) {
				log.Info("[ROUTER] custom proxy regexp matched", "host", host, "pattern", re.String())
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

// AddDirectIP 向自定义直连 IP 集合中添加一个 IP（线程安全）。
func (r *Router) AddDirectIP(ip string) {
	r.customMu.Lock()
	r.customDirectIPs[ip] = struct{}{}
	r.customMu.Unlock()
}

// AddProxyIP 向自定义代理 IP 集合中添加一个 IP（线程安全）。
func (r *Router) AddProxyIP(ip string) {
	r.customMu.Lock()
	r.customProxyIPs[ip] = struct{}{}
	r.customMu.Unlock()
}

// AddDirectDomain 向自定义直连域名集合中添加一个域名（线程安全）。
func (r *Router) AddDirectDomain(domain string) {
	r.customMu.Lock()
	r.customDirectDomains[domain] = struct{}{}
	r.customMu.Unlock()
}

// AddProxyDomain 向自定义代理域名集合中添加一个域名（线程安全）。
func (r *Router) AddProxyDomain(domain string) {
	r.customMu.Lock()
	r.customProxyDomains[domain] = struct{}{}
	r.customMu.Unlock()
}

// IsCustomDirectDomain 检查域名是否在自定义直连域名列表中
// （包括子域名匹配以及 regexp/glob 规则）。
func (r *Router) IsCustomDirectDomain(domain string) bool {
	r.customMu.RLock()
	defer r.customMu.RUnlock()
	if _, ok := r.customDirectDomains[domain]; ok {
		return true
	}
	for _, sub := range util.SubDomains(domain) {
		if _, ok := r.customDirectDomains[sub]; ok {
			return true
		}
	}
	for _, re := range r.customDirectRegexps {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

// IsCustomProxyDomain 检查域名是否在自定义代理域名列表中
// （包括子域名匹配以及 regexp/glob 规则）。
func (r *Router) IsCustomProxyDomain(domain string) bool {
	r.customMu.RLock()
	defer r.customMu.RUnlock()
	if _, ok := r.customProxyDomains[domain]; ok {
		return true
	}
	for _, sub := range util.SubDomains(domain) {
		if _, ok := r.customProxyDomains[sub]; ok {
			return true
		}
	}
	for _, re := range r.customProxyRegexps {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

func (r *Router) ShouldIPV6Disable() bool {
	switch IPV6Rule(r.ipv6Rule.Load()) {
	case IPV6RuleEnable:
		return false
	case IPV6RuleAuto:
		if r.ipv6Networking.Load() && r.ServerIPV6() != "" {
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

// SetIPV6Info 记录 IPv6 网络是否可用以及解析出的服务器 IPv6 地址。
// 可以与读取方并发调用。
func (r *Router) SetIPV6Info(networking bool, serverIPV6 string) {
	r.ipv6Networking.Store(networking)
	r.serverIPV6.Store(&serverIPV6)
}

// ServerIPV6 返回解析出的服务器 IPv6 地址（不可用时返回 ""）。
func (r *Router) ServerIPV6() string {
	if p := r.serverIPV6.Load(); p != nil {
		return *p
	}
	return ""
}
