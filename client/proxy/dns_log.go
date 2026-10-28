package proxy

import (
	"log/slog"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

// dnsLogKey 是日志去重键：同一域名的 A/AAAA 是两次独立解析，各自算"首次"。DNS 名不区分
// 大小写，键必须像缓存与规则匹配那样归一，否则混合大小写查询会各自算首次。
func dnsLogKey(domain, qtype string) string {
	return strings.ToLower(domain) + "\x00" + qtype
}

// dnsLogOnce 记住已经以 Info 级别记录过的键，使 info 级别下每个域名只留一条查询和一条
// 结果，重复查询仍降到 debug。容量固定，超出后按插入顺序淘汰最旧的键。
type dnsLogOnce struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
	head  int
}

const dnsLogOnceCap = 4096

// mark 登记 key 并报告它此前是否没有出现过。
func (s *dnsLogOnce) mark(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.seen[key]; ok {
		return false
	}
	if s.seen == nil {
		s.seen = make(map[string]struct{}, dnsLogOnceCap)
	}
	if len(s.order) < dnsLogOnceCap {
		s.order = append(s.order, key)
	} else {
		delete(s.seen, s.order[s.head])
		s.order[s.head] = key
		s.head = (s.head + 1) % dnsLogOnceCap
	}
	s.seen[key] = struct{}{}
	return true
}

// dnsLogLevel 把"首次"映射成级别：首次 Info 留痕，重复查询只对 debug 可见。
func dnsLogLevel(first bool) slog.Level {
	if first {
		return slog.LevelInfo
	}
	return slog.LevelDebug
}

// logCacheHit 记录缓存命中。命中就是这条查询的应答：首次命中把应答写进 Info 行并消费首答，
// 否则缓存过期后的第一次真实解析会留下没有 query 行配对的 result 行。
func (d *dnsInterceptor) logCacheHit(plan dnsPlan, cached *dns.Msg) {
	if plan.first {
		d.answerLog.mark(dnsLogKey(plan.domain, plan.qtype))
		log.Info("[DNS_CACHE] hit", "domain", plan.domain, "qtype", plan.qtype,
			"direct", plan.direct, "answers", util.DNSAnswerStrings(cached))
		return
	}
	log.Debug("[DNS_CACHE] hit", "domain", plan.domain, "qtype", plan.qtype, "direct", plan.direct)
}
