package dns

import "time"

// DNS 层的三个超时是三个不同 SLA 的概念，这里是它们的唯一事实来源。
// 三层只在"启动期预解析"路径上叠加使用，关系是：
//
//	PreResolveTimeout            // 一次完整预解析的总预算（内置池 + 系统兜底）
//	└─ 内置池：PreResolveTimeout - ResolveItemTimeout（留给系统兜底）
//	   └─ 每个 DNS 条目：ResolveItemTimeout（A 与 AAAA 并发共享）
//
// 池里 6 项 × ResolveItemTimeout = 12s，因此 14s 恰好覆盖全池并留 2s 给系统
// 兜底：既让每一项都有公平机会，又让总启动延迟有界。
//
// 在线服务路径不使用这三个值：它走 config.Timeouts 派生族（Dial/DNSResp/
// UDPIdle，随用户配置的基础超时变化），两者的 SLA 不同——在线查询可以让客户端
// 重试，而启动期必须在有限时间内让出。
const (
	// dnsQueryTimeout 是单次上游 DNS 往返的默认上限（dns.Client.Timeout），
	// 由 lookup（预解析/IPv6 解析）与本地转发服务器（ForwardServer）共用。
	// 它是"一次往返"的上限，不带任何重试或遍历语义。
	dnsQueryTimeout = 5 * time.Second

	// PreResolveTimeout 是一次完整预解析的总预算：从第一个内置 DNS 服务器到
	// 系统 DNS 兜底结束。启动期（runner.Run）、服务端 IPv6 解析（client.New）
	// 与 TUN helper 预解析三条路径共用它，避免同一个概念存三份拷贝。
	PreResolveTimeout = 14 * time.Second
)

// ResolveItemTimeout 是预解析中"每个 DNS 条目"的上限：该条目的 A 与 AAAA
// 查询并发进行、共享这段时间。它保证池里每一项都有公平机会——否则一个黑洞
// 服务器（丢包而非立即拒绝）会独吞整个总预算。
//
// 它同时是系统 DNS 兜底的预留量（见 WithSystemDNSFallbackReserve）：兜底至少
// 能拿到一个完整条目的预算。
//
// 它是变量（而非常量）以便测试缩短它，与 runner.serverStartupResolveTimeout
// 的做法一致。
var ResolveItemTimeout = 2 * time.Second
