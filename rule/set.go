// Package rule 是"规则文件 → 匹配集合"的唯一实现，客户端路由与服务端链式代理共用。解析按
// `regexp:` → 含 `*` 的 glob → CIDR → IP → 域名 的优先级；失败是否致命由调用方决定。
package rule

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/nange/easyss/v3/util"
)

type Kind uint8

const (
	KindDomain Kind = iota
	KindIP
	KindCIDR
	KindGlob
	KindRegexp
)

func (k Kind) String() string {
	switch k {
	case KindIP:
		return "ip"
	case KindCIDR:
		return "cidr"
	case KindGlob:
		return "glob"
	case KindRegexp:
		return "regexp"
	default:
		return "domain"
	}
}

// Error 是一条无法解析的规则。Index 由 ParseFile 填成行号，调用方据此给出可定位的告警。
type Error struct {
	Index int
	Line  string
	Kind  Kind
	Err   error
}

func (e *Error) Error() string {
	return fmt.Sprintf("line %d: invalid %s rule %q: %v", e.Index+1, e.Kind, e.Line, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

type Options struct {
	// AllowComments 为 true 时跳过空行与以 '#' 开头的整行注释。行尾注释刻意不支持：
	// '#' 在正则与 glob 里可能合法，就地截断会把一条有效规则改写成另一条。
	AllowComments bool
}

// Set 是可并发读写的规则集合，所有匹配方法都不要求调用方加锁；零值可直接使用，但永不命中。
type Set struct {
	mu       sync.RWMutex
	domains  map[string]struct{}
	ips      map[string]struct{}
	cidrs    []*net.IPNet
	patterns []*regexp.Regexp

	counts [5]int
}

func New() *Set {
	return &Set{
		domains: make(map[string]struct{}),
		ips:     make(map[string]struct{}),
	}
}

// ParseLines 解析一组规则行。返回的 Set 永不为 nil：无法解析的行被跳过并收进错误列表，
// 集合里保留其余可用规则。
func ParseLines(lines []string, opts Options) (*Set, []*Error) {
	b := &builder{s: New()}
	var errs []*Error
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || (opts.AllowComments && strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if err := b.add(trimmed); err != nil {
			err.Index = i
			err.Line = trimmed
			errs = append(errs, err)
		}
	}
	return b.s, errs
}

func (s *Set) Counts() (domains, ips, cidrs, patterns int) {
	if s == nil {
		return 0, 0, 0, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.counts[KindDomain], s.counts[KindIP], s.counts[KindCIDR],
		s.counts[KindGlob] + s.counts[KindRegexp]
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, n := range s.counts {
		total += n
	}
	return total
}

// MatchHost 报告 host 是否命中集合。归一化由 MatchHostKind 统一完成，因此 "host:port"、大写
// 域名与 FQDN 都得到相同结论。
func (s *Set) MatchHost(host string) bool {
	_, ok := s.MatchHostKind(host)
	return ok
}

func (s *Set) MatchHostKind(host string) (Kind, bool) {
	if s == nil {
		return KindDomain, false
	}
	host = NormalizeHost(host)
	if host == "" {
		return KindDomain, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if ip := net.ParseIP(host); ip != nil {
		return s.matchIPLocked(ip)
	}
	return s.matchDomainLocked(host)
}

// HasDomain 报告 domain（或任一父域名）是否出现在域名集合里，或命中 glob/regexp 模式。
// 与 MatchHost 的唯一区别是绝不按 IP 处理。
func (s *Set) HasDomain(domain string) bool {
	if s == nil {
		return false
	}
	domain = NormalizeHost(domain)
	if domain == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.matchDomainLocked(domain)
	return ok
}

func (s *Set) matchIPLocked(ip net.IP) (Kind, bool) {
	if _, ok := s.ips[canonicalIP(ip)]; ok {
		return KindIP, true
	}
	for _, cidr := range s.cidrs {
		if cidr.Contains(ip) {
			return KindCIDR, true
		}
	}
	return KindIP, false
}

func (s *Set) matchDomainLocked(host string) (Kind, bool) {
	if _, ok := s.domains[host]; ok {
		return KindDomain, true
	}
	for _, sub := range util.SubDomains(host) {
		if _, ok := s.domains[sub]; ok {
			return KindDomain, true
		}
	}
	for _, re := range s.patterns {
		if re.MatchString(host) {
			return KindRegexp, true
		}
	}
	return KindDomain, false
}

// AddIP 加入一个字面 IP，报告它是否新增。IPv4-mapped 的 IPv6 会折叠为 IPv4，使学习路径写
// 入的 ::ffff:1.2.3.4 与拨号目标里的 1.2.3.4 能匹配上；返回值供动态学习维护条目预算。
func (s *Set) AddIP(ip string) bool {
	if s == nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	key := canonicalIP(parsed)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addIPLocked(key)
}

func (s *Set) AddDomain(domain string) bool {
	if s == nil {
		return false
	}
	key := NormalizeHost(domain)
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addDomainLocked(key)
}

func (s *Set) addIPLocked(key string) bool {
	if s.ips == nil {
		s.ips = make(map[string]struct{})
	}
	if _, ok := s.ips[key]; ok {
		return false
	}
	s.ips[key] = struct{}{}
	s.counts[KindIP]++
	return true
}

func (s *Set) addDomainLocked(key string) bool {
	if s.domains == nil {
		s.domains = make(map[string]struct{})
	}
	if _, ok := s.domains[key]; ok {
		return false
	}
	s.domains[key] = struct{}{}
	s.counts[KindDomain]++
	return true
}

type builder struct {
	s *Set
}

func (b *builder) add(line string) *Error {
	switch {
	case strings.HasPrefix(line, "regexp:"):
		pattern := strings.TrimPrefix(line, "regexp:")
		if pattern == "" {
			return &Error{Kind: KindRegexp, Err: errors.New("empty pattern")}
		}
		// (?i)：DNS 名大小写不敏感，用户写的 [A-Z] 常常只是笔误。
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return &Error{Kind: KindRegexp, Err: err}
		}
		b.s.patterns = append(b.s.patterns, re)
		b.s.counts[KindRegexp]++
		return nil

	case strings.Contains(line, "*"):
		// 含 * 但没有 regexp: 前缀 → glob。GlobToRegexp 只给 ^...$ 锚点，大小写不敏感
		// 仍需在这里补上。
		re, err := util.GlobToRegexp(line)
		if err != nil {
			return &Error{Kind: KindGlob, Err: err}
		}
		re, err = regexp.Compile("(?i)" + re.String())
		if err != nil {
			return &Error{Kind: KindGlob, Err: err}
		}
		b.s.patterns = append(b.s.patterns, re)
		b.s.counts[KindGlob]++
		return nil
	}

	if _, ipnet, err := net.ParseCIDR(line); err == nil && ipnet != nil {
		b.s.cidrs = append(b.s.cidrs, ipnet)
		b.s.counts[KindCIDR]++
		return nil
	}

	if ip := net.ParseIP(line); ip != nil {
		b.s.addIPLocked(canonicalIP(ip))
		return nil
	}

	// 剩下的都按域名处理，只做小写归一、不做格式校验：允许只匹配标签片段的写法。
	b.s.addDomainLocked(normalizeDomainKey(line))
	return nil
}

// NormalizeHost 把 host 归一化成匹配用的形式：去端口、去 FQDN 尾部点号、转小写，IPv6 字面量
// 去方括号。这是"同一个主机在不同调用点得到同一结论"的唯一入口。
func NormalizeHost(host string) string {
	if host == "" {
		return ""
	}
	// 快路径：只有带端口或方括号的形态才可能拆分。裸域名上直接调 SplitHostPort 失败会分配
	// 一个 error，而本函数在每条连接的匹配路径上都要跑。
	if strings.IndexByte(host, ':') >= 0 || strings.HasPrefix(host, "[") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			// 形如 "[2001:db8::1]"（无端口）：SplitHostPort 会失败。
			host = host[1 : len(host)-1]
		}
	}
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// normalizeDomainKey 是规则条目的归一化：条目不可能带端口或方括号，因此省掉 NormalizeHost
// 里的端口探测（30 万行内置列表上那两次字符串扫描是可见的启动成本）。
func normalizeDomainKey(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// canonicalIP 返回 IP 的规范字符串：IPv4 与 IPv4-mapped 的 IPv6 都折叠成 IPv4 点分形式。
func canonicalIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}
