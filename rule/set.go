// Package rule 是"规则文件 → 匹配集合"的唯一实现。
//
// 客户端路由（client/router 的自定义直连/代理文件）与服务端链式代理
// （server/nextproxy 的 next_proxy_file）此前各有一份逐行解析、各自维护
// IP/CIDR/域名/regexp 四个集合、各自遍历子域名与模式。两份实现已经在语义上
// 漂移——大小写、IPv4-mapped 归一化、失败是否上报都不同——因此这里把它们收成
// 一份：
//
//   - 解析：ParseLines/ParseFile 按 `regexp:` → 含 `*` 的 glob → CIDR → IP →
//     域名 的优先级识别每一行（与 README 的"匹配规则"一节一致），并**返回**
//     每条失败规则（含行号）而不是静默丢弃；
//   - 归一化：IP 折叠为规范形式（IPv4-mapped 的 ::ffff:a.b.c.d 变成 a.b.c.d），
//     域名统一小写，glob 与 regexp 按大小写不敏感编译；
//   - 匹配：Set.MatchHost 是"这个 host 是否命中"的唯一入口。
//
// 包本身不决定"解析失败是否致命"：Set 收集错误并照常工作，由调用方
// （router 记启动告警、nextproxy 报错）决定策略。这条分界是刻意的——两边对
// 错误容忍度的要求本来就不同，共享的是解析与匹配，不是策略。
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

// Kind 是一条规则的类别。
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

// Error 是一条无法解析（或无法安全编译）的规则。Index 是它在输入里的下标
// （ParseFile 自动填充行号），调用方据此给出可定位的告警。
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

// Options 控制解析行为。
type Options struct {
	// AllowComments 为 true 时跳过空行与以 '#' 开头的整行注释。行尾注释**不**
	// 支持：正则与 glob 里都可能合法地出现 '#'，就地截断会把一条有效规则改写成
	// 另一条。README 的示例因此把注释单独成行。
	AllowComments bool
}

// Set 是一个可并发读写的规则集合。所有匹配方法都不要求调用方加锁。
//
// 零值可直接使用（匹配一律不命中）；生产路径应通过 ParseLines/ParseFile 构建。
type Set struct {
	mu       sync.RWMutex
	domains  map[string]struct{}
	ips      map[string]struct{}
	cidrs    []*net.IPNet
	patterns []*regexp.Regexp

	// counts 记录各类规则条数，供调用方打"加载了什么"的启动日志。
	counts [5]int
}

// New 返回一个空的 Set。
func New() *Set {
	return &Set{
		domains: make(map[string]struct{}),
		ips:     make(map[string]struct{}),
	}
}

// ParseLines 解析一组规则行。返回的 Set 永不为 nil：无法解析的行被跳过并
// 收集进错误列表，集合里保留其余可用规则。
func ParseLines(lines []string, opts Options) (*Set, []*Error) {
	// 构造期不加锁：Set 尚未发布，逐行 parse 直接用 builder，最后一次性发布。
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

// Counts 返回各类规则的条目数：域名、IP、CIDR、模式（glob + regexp 合计）。
func (s *Set) Counts() (domains, ips, cidrs, patterns int) {
	if s == nil {
		return 0, 0, 0, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.counts[KindDomain], s.counts[KindIP], s.counts[KindCIDR],
		s.counts[KindGlob] + s.counts[KindRegexp]
}

// Len 返回规则总条数。
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

// MatchHost 报告 host 是否命中集合：IP 按精确/网段匹配，域名按"自身或其父域名
// 命中"以及 glob/regexp 模式匹配。
//
// host 的归一化（去端口、小写、去尾部点号）由这里统一完成，因此调用方传入
// "host:port"、大写域名或 FQDN（example.com.）都能得到相同结论。
func (s *Set) MatchHost(host string) bool {
	_, ok := s.MatchHostKind(host)
	return ok
}

// MatchHostKind 与 MatchHost 判定相同，但额外返回命中的规则形态。调用方用它
// 打"为什么这条请求走了直连"的日志，而不必自己再实现一遍匹配。
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

// MatchIP 报告 ip 是否命中精确条目或网段。它用于"已经解析出地址"的调用方
// （例如从 DNS 应答里学到的地址）。
func (s *Set) MatchIP(ip string) bool {
	if s == nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.matchIPLocked(parsed)
	return ok
}

// HasDomain 报告 domain（或它的任一父域名）是否精确出现在域名集合里，以及
// 是否命中任一 glob/regexp 模式。它与 MatchHost 的区别只有一点：绝不按 IP
// 处理，因此调用方可以放心传入一个长得像 IP 的域名。
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

// AddIP 向集合里加入一个字面 IP（线程安全），报告它是否是新增条目。
// IPv4-mapped 的 IPv6 会被折叠为 IPv4，使学习路径写入的 ::ffff:1.2.3.4 与
// 拨号目标里的 1.2.3.4 能匹配上。
//
// 返回"是否新增"是给动态学习用的：调用方需要用它维护有界的条目预算，否则
// 重复学习同一个地址会不断消耗预算。
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

// AddDomain 向集合里加入一个域名（线程安全），报告它是否是新增条目。
// 域名统一小写，与匹配侧一致。
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

// builder 是构造期（未发布）的写入器，不持锁。
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
		// (?i)：DNS 名本身大小写不敏感，用户写的 [A-Z] 却常常只是笔误。
		// 统一按大小写不敏感编译，使 "Example.COM" 与 "example.com" 结论一致。
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return &Error{Kind: KindRegexp, Err: err}
		}
		b.s.patterns = append(b.s.patterns, re)
		b.s.counts[KindRegexp]++
		return nil

	case strings.Contains(line, "*"):
		// 含 * 但没有 regexp: 前缀 → glob。GlobToRegexp 只给 ^...$ 锚点，
		// 大小写不敏感仍需在这里补上（理由同上）。
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

	// 剩下的都按域名处理。这里只做小写归一，不做格式校验：规则文件里允许出现
	// 只匹配标签片段的写法（例如单标签域名），历史上也能命中。
	b.s.addDomainLocked(NormalizeHost(line))
	return nil
}

// NormalizeHost 把 host 归一化成匹配用的形式：去掉可能的端口、去掉尾部点号
// （FQDN）、转小写。IPv6 字面量保持原样（去掉方括号）。
//
// 它是"同一个主机在不同调用点得到同一个结论"的前提：DNS 缓存以小写为键、
// qname 带尾部点号、拨号目标带端口，而规则文件里的条目是人写的裸域名。
func NormalizeHost(host string) string {
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		// 形如 "[2001:db8::1]"（无端口）：SplitHostPort 会失败。
		host = host[1 : len(host)-1]
	}
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// canonicalIP 返回 IP 的规范字符串：IPv4 与 IPv4-mapped 的 IPv6 都折叠成
// IPv4 点分形式，其余走 net.IP.String()。
func canonicalIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}
