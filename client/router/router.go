package router

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/nange/easyss/v3/assets"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/rule"
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

// GeoSite 是内置直连/屏蔽域名列表。它只是 rule.DomainSet 的类型别名：
// 解析（含 full:/regexp: 前缀）、大小写归一化与父域名展开都由 rule 包
// 统一实现，本包不再维护第二份。
type GeoSite = rule.DomainSet

// NewGeoSite 解析内置 geosite 列表。无法编译的正则被跳过——内置列表由发布
// 流程生成，出错属于数据缺陷而不是用户配置错误，因此只记一条告警。
func NewGeoSite(data []byte) *GeoSite {
	gs, skipped := rule.ParseDomainSet(data)
	if skipped > 0 {
		log.Warn("[ROUTER] skipped unparsable regexp entries in the builtin list", "count", skipped)
	}
	return gs
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

	// customDirect/customProxy 是配置文件与动态学习共用的两个规则集合。
	// direct/proxy 两半此前是八个字段、四对几乎逐行重复的匹配函数（dupl 报了
	// 4 处），现在各自只是一个 rule.Set。
	customDirect *rule.Set
	customProxy  *rule.Set

	// customFileErr 记录加载自定义直连/代理规则文件时遇到的失败。
	// 加载刻意设计为非致命（路由器仍保留内置规则），但该错误会作为启动警告
	// 暴露出来，让用户知道自己的自定义规则没有被（完整）应用。
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
		customDirect:  rule.New(),
		customProxy:   rule.New(),
	}
	r.proxyRule.Store(int32(cfg.ProxyRule))
	r.ipv6Rule.Store(int32(cfg.IPV6Rule))
	r.SetIPV6Info(cfg.IPV6NetWorking, cfg.ServerIPV6)

	if err := r.loadCustomRuleFiles(); err != nil {
		r.customFileErr = fmt.Errorf("load custom rule file: %w", err)
		log.Error("[ROUTER] load custom ip/domains", "err", err)
	}

	return r, nil
}

// CustomFileError 返回加载自定义直连/代理规则文件时遇到的失败，
// 两个文件都加载成功时返回 nil。
func (r *Router) CustomFileError() error {
	return r.customFileErr
}

// loadCustomRuleFiles 读取并装载两个规则文件。行级错误不中止加载（其余规则
// 仍然生效），但会被汇总进 CustomFileErr，让用户在启动时就知道有规则没被应用
// ——此前这些错误是静默丢弃的，写错的正则或 glob 只会表现为"规则没生效"。
func (r *Router) loadCustomRuleFiles() error {
	var errs []error
	load := func(path, label string, dst **rule.Set) {
		if path == "" {
			return
		}
		set, parseErrs, err := rule.ParseFile(path, rule.Options{AllowComments: true})
		if err != nil {
			errs = append(errs, err)
			return
		}
		if len(parseErrs) > 0 {
			errs = append(errs, rule.FileError(path, parseErrs))
		}
		*dst = set

		domains, ips, cidrs, patterns := set.Counts()
		log.Info("[ROUTER] loaded "+label+" file",
			"file", path,
			"domains", domains,
			"ips", ips,
			"cidrs", cidrs,
			"patterns", patterns,
		)
	}
	load(r.cfg.DirectFile, "direct", &r.customDirect)
	load(r.cfg.ProxyFile, "proxy", &r.customProxy)
	return errors.Join(errs...)
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
	mode := ProxyRule(r.proxyRule.Load())
	if mode == ProxyRuleDirect || r.isLANHost(host) {
		return HostRuleDirect
	}
	if mode == ProxyRuleProxy {
		return HostRuleProxy
	}
	// 命中日志只在这里打一次：两个规则集合的匹配各自只返回布尔值，因此
	// "为什么这条请求走了直连"仍能在日志里看到，而匹配逻辑不必知道日志格式。
	if match, kind := r.hostMatchCustom(r.customDirect, host); match {
		log.Info("[ROUTER] custom direct matched", "host", host, "rule", kind)
		return HostRuleDirect
	}
	if match, kind := r.hostMatchCustom(r.customProxy, host); match {
		log.Info("[ROUTER] custom proxy matched", "host", host, "rule", kind)
		return HostRuleProxy
	}
	if mode == ProxyRuleAutoBlock && !util.IsIP(host) {
		if r.geoSiteDirect.Match(host, false) {
			return HostRuleDirect
		}
		if r.geoSiteBlock.Match(host, true) {
			return HostRuleBlock
		}
	}
	if mode == ProxyRuleReverseAuto && !r.hostAtCN(host) {
		return HostRuleDirect
	}
	if mode != ProxyRuleReverseAuto && r.hostAtCN(host) {
		return HostRuleDirect
	}
	return HostRuleProxy
}

// hostMatchCustomRule 报告 host 是否命中给定集合（不含日志）。
func (r *Router) hostMatchCustomRule(set *rule.Set, host string) bool {
	ok, _ := r.hostMatchCustom(set, host)
	return ok
}

// hostMatchCustom 在给定集合里匹配 host，并返回命中的规则形态（用于日志）。
func (r *Router) hostMatchCustom(set *rule.Set, host string) (bool, string) {
	kind, ok := set.MatchHostKind(host)
	if !ok {
		return false, ""
	}
	return true, kind.String()
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
	return r.geoSiteDirect.Match(host, true)
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
	// 与 rule 包一致：host 在这里可能带端口、可能是 FQDN 或大写形式。
	host = rule.NormalizeHost(host)
	if host == "localhost" {
		return true
	}
	return util.IsLANIP(host)
}

// AddDirectIP 向自定义直连 IP 集合中添加一个 IP（线程安全）。
func (r *Router) AddDirectIP(ip string) {
	r.customDirect.AddIP(ip)
}

// AddProxyIP 向自定义代理 IP 集合中添加一个 IP（线程安全）。
func (r *Router) AddProxyIP(ip string) {
	r.customProxy.AddIP(ip)
}

// AddDirectDomain 向自定义直连域名集合中添加一个域名（线程安全）。
func (r *Router) AddDirectDomain(domain string) {
	r.customDirect.AddDomain(domain)
}

// AddProxyDomain 向自定义代理域名集合中添加一个域名（线程安全）。
func (r *Router) AddProxyDomain(domain string) {
	r.customProxy.AddDomain(domain)
}

// IsCustomDirectDomain 检查域名是否在自定义直连域名列表中
// （包括子域名匹配以及 regexp/glob 规则）。
func (r *Router) IsCustomDirectDomain(domain string) bool {
	return r.isCustomDomain(r.customDirect, domain)
}

// IsCustomProxyDomain 检查域名是否在自定义代理域名列表中
// （包括子域名匹配以及 regexp/glob 规则）。
func (r *Router) IsCustomProxyDomain(domain string) bool {
	return r.isCustomDomain(r.customProxy, domain)
}

func (r *Router) isCustomDomain(set *rule.Set, domain string) bool {
	if r == nil || set == nil {
		return false
	}
	return set.HasDomain(domain)
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
