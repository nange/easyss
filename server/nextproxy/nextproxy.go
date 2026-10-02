package nextproxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	xproxy "golang.org/x/net/proxy"
)

type NextProxy struct {
	url         *url.URL
	enableUDP   bool
	allHost     bool
	dialTimeout time.Duration

	mu             sync.RWMutex
	ips            map[string]struct{}
	cidrIPs        []*net.IPNet
	domains        map[string]struct{}
	domainPatterns []*regexp.Regexp

	// learnedIPs/learnedDomains 只统计由 AddIP/AddDomain 添加的条目。
	// 上面的 map 中还包含文件配置的条目，因此不能用 len(ips)/len(domains)
	// 作为学习预算：否则一个较大的代理配置文件会禁用动态学习。
	learnedIPs     int
	learnedDomains int
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
		if strings.HasPrefix(k, "regexp:") {
			re, err := regexp.Compile(k[7:])
			if err == nil {
				np.domainPatterns = append(np.domainPatterns, re)
			}
			continue
		}
		if strings.Contains(k, "*") {
			re, err := util.GlobToRegexp(k)
			if err == nil {
				np.domainPatterns = append(np.domainPatterns, re)
			}
			continue
		}
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
	log.Info("[NEXTPROXY] loaded proxy file", "file", proxyFile, "total", len(entries), "ips", len(np.ips), "cidrs", len(np.cidrIPs), "domains", len(np.domains), "patterns", len(np.domainPatterns))

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
		return np.matchesDomainLocked(host)
	}
	return false
}

// IsCustomDomain 检查域名是否在自定义域名列表中，
// 包括子域名匹配以及 glob/regexp 模式。
func (np *NextProxy) IsCustomDomain(domain string) bool {
	if np == nil {
		return false
	}

	np.mu.RLock()
	defer np.mu.RUnlock()

	return np.matchesDomainLocked(domain)
}

// matchesDomainLocked 报告 host、其任一父域名或任一配置模式是否命中配置的
// 域名集合。调用方必须持有 np.mu：ShouldProxy 和 IsCustomDomain 是它的
// 仅有两个调用方，此前各自维护一份相同的遍历逻辑副本。
func (np *NextProxy) matchesDomainLocked(host string) bool {
	if _, ok := np.domains[host]; ok {
		return true
	}
	for _, sub := range util.SubDomains(host) {
		if _, ok := np.domains[sub]; ok {
			return true
		}
	}
	for _, re := range np.domainPatterns {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// maxLearnedEntries 限制动态学习的 IP/域名集合的大小：自定义域名的 DNS 响应
// 会在每次查询时喂给 AddIP/AddDomain，长期运行在大型 CDN 池（或记录频繁轮换
// 的域名）之后的服务端若不加限制，这些 map 会无限增长。集合达到上限后学习
// 停止；配置（文件加载）的条目不受影响。
const maxLearnedEntries = 4096

// AddIP 向路由列表中添加一个 IP（线程安全）。学习的 IP 会做归一化
// （IPv4 映射的 IPv6 折叠为 IPv4），以便与 dial 目标中观测到的字面 IP
// 匹配。超过 maxLearnedEntries 后条目被丢弃，以保持集合有界。
func (np *NextProxy) AddIP(ip string) {
	if np == nil {
		return
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		if ip4 := parsed.To4(); ip4 != nil {
			ip = ip4.String()
		} else {
			ip = parsed.String()
		}
	}
	np.mu.Lock()
	if _, exists := np.ips[ip]; !exists && np.learnedIPs < maxLearnedEntries {
		np.ips[ip] = struct{}{}
		np.learnedIPs++
	}
	np.mu.Unlock()
}

// AddDomain 向路由列表中添加一个域名（线程安全）。超过 maxLearnedEntries
// 后条目被丢弃，以保持集合有界。
func (np *NextProxy) AddDomain(domain string) {
	if np == nil {
		return
	}
	np.mu.Lock()
	if _, exists := np.domains[domain]; !exists && np.learnedDomains < maxLearnedEntries {
		np.domains[domain] = struct{}{}
		np.learnedDomains++
	}
	np.mu.Unlock()
}

// SetDialTimeout 设置拨号连接 SOCKS5 代理的超时时间。
func (np *NextProxy) SetDialTimeout(d time.Duration) {
	if np == nil {
		return
	}
	np.dialTimeout = d
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

	dialTimeout := np.dialTimeout
	if dialTimeout <= 0 {
		dialTimeout = config.DefaultDialTimeout
	}

	// forward 是 SOCKS5 客户端拨上游代理时使用的底层拨号函数（等价于旧库的
	// c.DialTCP）：只拨上游代理地址，并使用带 Timeout 的 net.Dialer。
	dialer := &net.Dialer{Timeout: dialTimeout}
	forward := socksDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	})

	var auth *xproxy.Auth
	if username != "" || password != "" {
		auth = &xproxy.Auth{User: username, Password: password}
	}
	d, err := xproxy.SOCKS5("tcp", np.url.Host, auth, forward)
	if err != nil {
		return nil, fmt.Errorf("create socks5 dialer: %w", err)
	}

	// x/net/proxy 的 SOCKS5 拨号器实现了 DialContext：ctx 在拨号阶段生效，
	// 并且会透传给上面的 forward，因此不再需要"goroutine + 结果 channel +
	// 放弃后排空"的手工取消编排——调用方取消时，进行中的拨号会被直接中止。
	//
	// 该库也不设置任何 deadline（全包无 SetDeadline），所以旧库 Negotiate()
	// 留下握手 deadline、需要在成功后手工清除的那段补偿一并消失。
	cd, ok := d.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks5 dialer %T does not support context", d)
	}
	conn, err := cd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial %s: %w", addr, err)
	}
	return conn, nil
}

// socksDialerFunc 是 xproxy.Dialer + ContextDialer 的函数式适配器。它让
// nextproxy 能把"带 Timeout 的 net.Dialer"直接当作 SOCKS5 客户端的底层拨号
// 函数注入，同时保留 ctx 取消能力（net.Dialer.DialContext 原生支持）。
type socksDialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f socksDialerFunc) Dial(network, address string) (net.Conn, error) {
	return f(context.Background(), network, address)
}

func (f socksDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// Host 以 "host:port" 形式返回上游代理地址（nil 接收者时返回 ""）。
// 调用方只需要它用于拨号和日志，因此不暴露内部的 *url.URL。
func (np *NextProxy) Host() string {
	if np == nil || np.url == nil {
		return ""
	}
	return np.url.Host
}

func (np *NextProxy) EnableUDP() bool {
	if np == nil {
		return false
	}
	return np.enableUDP
}
