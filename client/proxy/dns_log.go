package proxy

import (
	"log/slog"
	"sync"
)

// dnsLogKey 是日志去重键：同一域名的 A/AAAA 是两次独立解析，各自算"首次"。
func dnsLogKey(domain, qtype string) string {
	return domain + "\x00" + qtype
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
