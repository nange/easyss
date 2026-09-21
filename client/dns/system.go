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

// SystemDNSServers 以 host:port 地址的形式返回系统 DNS 服务器，从操作系统
// 惰性发现并短暂缓存。当所有内置直连 DNS 服务器都不可用时作为回退使用。
// 空结果也会被缓存，这样失败的发现（例如缓慢的 ipconfig 调用）不会在每次
// DNS 查询时重复执行。
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

// WithSystemDNSFallbackReserve 返回内置 DNS 分支应使用的 context：ctx 带截止
// 时间且剩余预算大于预留量时，把内置分支的截止时间提前一个 ResolveItemTimeout
// （即一个完整条目的预算），这样系统 DNS 兜底至少还能拿到这段时间。
//
// 内置 DNS 若是黑洞（丢包，而不是 RST/SERVFAIL 那种立即失败），单次查询会一直
// 等到超时；没有这层切分，预解析的整个预算会被内置服务器吃掉，随后复用同一个
// （已过期的）context 的系统 DNS 兜底就会在毫秒内以 dial i/o timeout 全部失败
// ——即使系统 DNS（DHCP/内网解析器）本身完全可用。
//
// 无截止时间（调用方不设总预算）或剩余预算已不足预留量时原样返回，不做切分。
// 覆盖内置 + 系统两段分支的调用方应在进入内置分支前调用它，并把返回的 context
// 只用于内置分支；系统兜底分支继续用原来的 ctx，从而仍然受总预算约束。
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
