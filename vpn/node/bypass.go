package vpnnode

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	tailcat "github.com/tailscale/tailcat"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// bypassTTL 是 DERP 主机名解析结果的缓存寿命。
//
// 缓存的意义是把"每次开启 TUN 都解析一遍"变成"最多每 10 分钟解析一次"，同时
// 让一次临时的解析失败不至于立刻丢掉绕行路由（失败时退回上一次的结果）。TTL
// 则保证一个长期运行的进程不会永远用一个已经搬走的地址。
const bypassTTL = 10 * time.Minute

// BypassOptions 是构造 Bypass 的输入。
type BypassOptions struct {
	// LocalDERPAddr 是本节点自己通告的 DERP host:port（见 Config.DERPAddr），
	// 也就是本地标记的 S。它由本节点的 tailcat Server 连接（对端面要接入中继）。
	LocalDERPAddr string

	// Peers 是要访问的对端：每个地址内嵌的 DERP 主机都要绕行。
	//
	// 跨 S 部署时这一步必需：A 访问 B 用的是 **B 地址里** 的 DERP，而不是 A
	// 本地标记的 S（见 docs/vpn-design.md 3.3），因此并集必须同时包含两者。
	Peers []PeerRef
}

// Bypass 计算并缓存"必须绕行 TUN 的 DERP 主机 IPv4"。
//
// 为什么必须有它：relay_only=true 时 magicsock 不建任何 UDP socket，到 DERP 主机的
// TCP 连接是 tailcat 唯一的出网通道；而 TUN 把除 0.0.0.0/8 外的全部 IPv4 都路由进
// 设备（见 docs/vpn-design.md 8.1、8.2）。没有一条更具体的 /32 主机路由，那条 TCP
// 连接会被自己的 TUN 捕获，经 tun2socks 回到 easyss 的 SOCKS5，形成环路。
//
// 只处理 IPv4：绕行由创建脚本按 /32 主机路由安装（8.2），三平台的脚本参数也按这一
// 形态设计。一个只解析出 AAAA 的 DERP 主机无法绕行，此时明确告警而不是静默漏掉。
type Bypass struct {
	// localDERP 是本地 S 的主机名。它为字面 IP 或被 LocalIPs 覆盖时不产生查询。
	localDERP string
	// peers 是全部需要绕行的对端 DERP 主机名（去重、稳定排序）。
	peers []string

	// lookup 解析主机名。它是字段而不是直接调 net.DefaultResolver，以便测试注入
	// 确定的解析结果：真实解析需要网络，而这里的契约只关心"谁进了并集"。
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)

	mu    sync.Mutex
	cache map[string]bypassEntry
}

// bypassEntry 是一个主机名的解析结果与它的解析时刻。
type bypassEntry struct {
	addrs []netip.Addr
	at    time.Time
}

// NewBypass 构造绕行 IP 计算器。它不做任何网络活动：主机名的解析推迟到 IPs。
func NewBypass(opts BypassOptions) *Bypass {
	b := &Bypass{
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		},
		cache: make(map[string]bypassEntry),
	}

	if host, _, err := sharedconfig.SplitDERPAddr(opts.LocalDERPAddr); err == nil {
		b.localDERP = host
	} else {
		log.Warn("[VPN] cannot read the local DERP host to bypass the TUN routes", "derp_addr", opts.LocalDERPAddr, "err", err)
	}

	seen := make(map[string]bool)
	for _, p := range opts.Peers {
		hosts, err := derpHostsOf(p.Address)
		if err != nil {
			// 配置校验（NewConfig）已经拒收过坏地址，因此这里只可能是被绕过
			// 校验的调用方；告警而不是失败，TUN 的其余部分仍然可用。
			log.Warn("[VPN] cannot read the DERP host of a peer to bypass the TUN routes", "host_name", p.HostName, "err", err)
			continue
		}
		for _, h := range hosts {
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			b.peers = append(b.peers, h)
		}
	}
	slices.Sort(b.peers)
	return b
}

// IPs 返回本会话需要绕行 TUN 的 DERP 主机 IPv4 并集（去重、升序）。
//
// localIPs 是本地 S 已经解析好的地址（Core.publishServerIPs 的结果）。非空时不再
// 解析本地 DERP 主机名：那份结果就是隧道拨号使用的权威答案，此刻再查一次既没必要，
// 也可能撞上"TUN 路由正要安装、DNS 还没有可用出口"的窗口。
//
// 单个主机解析失败只影响它自己：其余主机的绕行照常安装，失败在日志里可见。
func (b *Bypass) IPs(ctx context.Context, localIPs []string) []netip.Addr {
	if b == nil {
		return nil
	}

	var out []netip.Addr
	if len(localIPs) > 0 {
		for _, s := range localIPs {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				log.Warn("[VPN] ignoring an unparsable local server address in the TUN bypass list", "addr", s, "err", err)
				continue
			}
			out = append(out, ip)
		}
	} else if b.localDERP != "" {
		out = append(out, b.resolve(ctx, b.localDERP)...)
	}
	for _, host := range b.peers {
		out = append(out, b.resolve(ctx, host)...)
	}

	return normalizeBypassAddrs(out)
}

// resolve 解析一个 DERP 主机，带 TTL 缓存与"失败退回上一次结果"。
func (b *Bypass) resolve(ctx context.Context, host string) []netip.Addr {
	if ip, err := netip.ParseAddr(host); err == nil {
		// 字面 IP 不需要解析；IPv6 字面量按文件头的说明跳过。
		if ip.Is4() {
			return []netip.Addr{ip.Unmap()}
		}
		log.Warn("[VPN] a DERP host is an IPv6 literal: its TUN bypass route is not installed (only IPv4 is supported)", "host", host)
		return nil
	}

	b.mu.Lock()
	entry, cached := b.cache[host]
	b.mu.Unlock()
	if cached && time.Since(entry.at) < bypassTTL {
		return entry.addrs
	}

	addrs, err := b.lookup(ctx, host)
	if err != nil {
		if cached && len(entry.addrs) > 0 {
			log.Warn("[VPN] re-resolving the DERP host failed, keeping the last known address for the TUN bypass",
				"host", host, "err", err)
			return entry.addrs
		}
		log.Warn("[VPN] cannot resolve the DERP host: no TUN bypass route can be installed for it, "+
			"so its traffic may be captured by the tunnel", "host", host, "err", err)
		return nil
	}

	addrs = normalizeBypassAddrs(addrs)
	if len(addrs) == 0 {
		log.Warn("[VPN] the DERP host has no IPv4 address: its TUN bypass route cannot be installed", "host", host)
		return nil
	}

	b.mu.Lock()
	b.cache[host] = bypassEntry{addrs: addrs, at: time.Now()}
	b.mu.Unlock()
	return addrs
}

// derpHostsOf 取出一个 tailcat 地址内嵌的全部 DERP 主机名。
//
// 地址必须是完整展开格式（NewConfig 已校验），因此 ci.Region 一定非空；短格式
// 地址在这里只会得到一个空结果，而它本来就会让 tailcat 去拉官方 DERPMap。
func derpHostsOf(addr string) ([]string, error) {
	ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		return nil, fmt.Errorf("parse tailcat address: %w", err)
	}
	var hosts []string
	for _, region := range ci.Region {
		if region == nil {
			continue
		}
		for _, node := range region.Nodes {
			if node == nil || node.HostName == "" {
				continue
			}
			hosts = append(hosts, node.HostName)
		}
	}
	return hosts, nil
}

// normalizeBypassAddrs 只保留 IPv4、去重并升序排序，使脚本参数与测试断言稳定。
func normalizeBypassAddrs(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsValid() || !a.Is4() {
			continue
		}
		a = a.Unmap()
		if slices.Contains(out, a) {
			continue
		}
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}
