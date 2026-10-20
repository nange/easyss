package dns

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

const systemDNSCacheTTL = 5 * time.Minute

// systemServers 给出去重后的系统 DNS 兜底地址（host:port）。生产实现是 *systemDNS，
// 测试用静态列表替换。
type systemServers interface {
	Servers() []string
}

// systemDNS 发现并缓存系统 DNS 服务器。缓存属于实例：测试构造独立实例即可避免
// 进程级状态互相污染。
type systemDNS struct {
	discover func() ([]string, error)

	mu     sync.Mutex
	cached []string
	at     time.Time
}

func newSystemDNS(discover func() ([]string, error)) *systemDNS {
	return &systemDNS{discover: discover}
}

// Servers 以 host:port 返回系统 DNS 服务器，惰性发现并短暂缓存。空结果也缓存，
// 失败发现（例如缓慢的 ipconfig）才不会在每次查询时重跑。
func (s *systemDNS) Servers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Since(s.at) < systemDNSCacheTTL {
		return s.cached
	}

	servers, err := s.discover()
	if err != nil {
		log.Warn("[DNS] get system dns servers", "err", err)
	}
	var addrs []string
	for _, server := range servers {
		if server == "" {
			continue
		}
		addrs = append(addrs, net.JoinHostPort(server, "53"))
	}
	s.cached = addrs
	s.at = time.Now()
	return addrs
}

func (s *systemDNS) reset() {
	s.mu.Lock()
	s.cached = nil
	s.at = time.Time{}
	s.mu.Unlock()
}

// defaultSystemDNS 是进程的唯一系统 DNS 发现器；ResetResolveState 清的就是它的缓存。
var defaultSystemDNS = newSystemDNS(util.SysDNS)

func SystemDNSServers() []string {
	return defaultSystemDNS.Servers()
}

// 把内置分支的截止时间提前一个 ResolveItemTimeout，给系统 DNS 兜底留出至少一个条目的预算；
// 内置 DNS 若是黑洞，兜底复用同一个已过期的 ctx 会立刻全部超时。返回的 ctx 只用于内置分支。
func WithSystemDNSFallbackReserve(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	builtinDeadline := deadline.Add(-ResolveItemTimeout)
	if !time.Now().Before(builtinDeadline) {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, builtinDeadline)
}
