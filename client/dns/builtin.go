package dns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
)

// 全部内置 DNS 都失败后跳过它们的时间；冷却结束即允许一次重试，网络恢复后能被重新探测到。
const builtinDNSCoolDown = 3 * time.Minute

var (
	builtinDNSMu     sync.Mutex
	builtinDNSDown   bool
	builtinDNSDownAt time.Time
)

func BuiltinDNSAvailable() bool {
	builtinDNSMu.Lock()
	defer builtinDNSMu.Unlock()
	if !builtinDNSDown {
		return true
	}
	return time.Since(builtinDNSDownAt) >= builtinDNSCoolDown
}

func MarkBuiltinDNSUnavailable() {
	builtinDNSMu.Lock()
	builtinDNSDown = true
	builtinDNSDownAt = time.Now()
	builtinDNSMu.Unlock()
}

func MarkBuiltinDNSAvailable() {
	builtinDNSMu.Lock()
	builtinDNSDown = false
	builtinDNSMu.Unlock()
}

// 三个状态互斥，调用方必须用 switch 显式处理。
type BuiltinRoute uint8

const (
	// 熔断器健康：先试内置池，失败再回退系统 DNS。
	BuiltinRouteFirst BuiltinRoute = iota
	// 熔断生效且有系统兜底：直接用系统 DNS，不碰内置池。
	BuiltinRouteSkip
	// 熔断生效但没有任何系统兜底：无视冷却继续试内置池，否则冷却期会变成彻底中断
	// （Android 上系统 DNS 对应用不可见正是这种情形）。
	BuiltinRouteRetry
)

func (r BuiltinRoute) String() string {
	switch r {
	case BuiltinRouteSkip:
		return "skip-builtin"
	case BuiltinRouteRetry:
		return "retry-builtin"
	default:
		return "builtin-first"
	}
}

// hasFailover 必须惰性求值：健康路径不该为一次预解析付出系统 DNS 发现的代价。只有确实存在
// 兜底时才跳过内置池，否则冷却期内每一次解析都会在空列表上立刻失败。
func BuiltinRouteFor(hasFailover func() bool) BuiltinRoute {
	if BuiltinDNSAvailable() {
		return BuiltinRouteFirst
	}
	if hasFailover() {
		return BuiltinRouteSkip
	}
	return BuiltinRouteRetry
}

// system 必须是惰性求值且过滤后的可用上游：拨不通的条目（自环地址、禁用 IPv6 时的 IPv6
// 地址）不能算兜底，否则熔断后会静默失去唯一的上游。健康路径不该为一次查询付系统 DNS
// 发现与自环过滤的代价，因此用函数而不是切片。
func QueryWithBuiltinFirst(builtin []string, system func() []string, invalidate func(), try func(servers []string) (*dns.Msg, error)) (*dns.Msg, error) {
	if system == nil {
		system = func() []string { return nil }
	}
	var (
		once    sync.Once
		servers []string
	)
	loadSystem := func() []string {
		once.Do(func() { servers = system() })
		return servers
	}
	// 失效判据集中在这里：trySystem 返回错误即整份兜底列表没给出可用应答。什么算"答过"
	// 由各调用方的 try 定义——转发路径要求权威 rcode（NOERROR/NXDOMAIN 才算答过），代理
	// 直连路径任何应答都算，所以 proxy 侧只有传输层失败才会作废。
	trySystem := func(upstreams []string) (*dns.Msg, error) {
		reply, err := try(upstreams)
		if err != nil && invalidate != nil {
			invalidate()
		}
		return reply, err
	}

	if len(builtin) == 0 {
		return trySystem(loadSystem())
	}
	route := BuiltinRouteFor(func() bool { return len(loadSystem()) > 0 })
	if route == BuiltinRouteSkip {
		return trySystem(loadSystem())
	}
	if route == BuiltinRouteRetry {
		// 必须是 Debug：本函数每条查询都会走到，Warn 会按查询刷屏。
		log.Debug("[DNS] builtin dns breaker is armed but no system dns is available, retrying builtin servers")
	}
	reply, err := try(builtin)
	if err == nil {
		MarkBuiltinDNSAvailable()
		return reply, nil
	}
	// 只有存在系统兜底时才置位：无兜底时熔断会让冷却期变成彻底中断。
	fallback := loadSystem()
	if len(fallback) > 0 {
		MarkBuiltinDNSUnavailable()
		log.Warn("[DNS] all builtin dns servers failed, fallback to system dns", "err", err)
	} else {
		log.Debug("[DNS] all builtin dns servers failed and no system dns is available", "err", err)
	}
	return trySystem(fallback)
}
