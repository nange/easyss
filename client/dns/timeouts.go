package dns

import "time"

// 三个超时只在启动期预解析路径上叠加：PreResolveTimeout 是总预算，内置池只分到
// PreResolveTimeout - ResolveItemTimeout（6 项 × 2s 之外余 2s 给系统兜底），条目内 A/AAAA 并发共享。
// 在线查询不用这三个值，走 config.Timeouts 派生族。
const (
	// dnsQueryTimeout 是单次上游 DNS 往返的上限（dns.Client.Timeout），由预解析与
	// 本地转发服务器（ForwardServer）共用，不带重试或遍历语义。
	dnsQueryTimeout = 5 * time.Second

	// PreResolveTimeout 是一次完整预解析的总预算，runner.Run、client.New 与 TUN helper
	// 三条路径共用，必须容纳一整个内置池加系统兜底。
	PreResolveTimeout = 14 * time.Second
)

// ResolveItemTimeout 是预解析中每个 DNS 条目的上限（A 与 AAAA 并发共享），保证池里每一项
// 都有公平机会——否则一个黑洞服务器（丢包而非立即拒绝）会独吞整个总预算。它同时是系统兜底
// 的预留量（见 WithSystemDNSFallbackReserve）。用变量是为了测试能缩短它。
var ResolveItemTimeout = 2 * time.Second
