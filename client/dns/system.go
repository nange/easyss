package dns

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

// sysDNSFunc 负责发现系统 DNS 服务器，可在测试中覆盖。
var sysDNSFunc = util.SysDNS

// systemDNSServersFunc 返回格式化后的系统 DNS 服务器列表，供回退路径使用，
// 可在测试中覆盖。
var systemDNSServersFunc = SystemDNSServers

const systemDNSCacheTTL = 5 * time.Minute

var (
	systemDNSMu     sync.Mutex
	systemDNSCached []string
	systemDNSTime   time.Time
)

// SystemDNSServers 以 host:port 返回系统 DNS 服务器，惰性发现并短暂缓存。空结果也缓存，
// 失败发现（例如缓慢的 ipconfig）才不会在每次查询时重跑。
func SystemDNSServers() []string {
	systemDNSMu.Lock()
	defer systemDNSMu.Unlock()

	if time.Since(systemDNSTime) < systemDNSCacheTTL {
		return systemDNSCached
	}

	servers, err := sysDNSFunc()
	if err != nil {
		log.Warn("[DNS] get system dns servers", "err", err)
	}
	var addrs []string
	for _, s := range servers {
		if s == "" {
			continue
		}
		addrs = append(addrs, net.JoinHostPort(s, "53"))
	}
	systemDNSCached = addrs
	systemDNSTime = time.Now()
	return addrs
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
