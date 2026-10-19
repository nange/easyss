package nextproxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/rule"
	xproxy "golang.org/x/net/proxy"
)

type NextProxy struct {
	url         *url.URL
	enableUDP   bool
	allHost     bool
	dialTimeout time.Duration

	// rules 是"目标是否走下一级代理"的规则集合：文件配置的条目与 DNS 学习
	// 到的条目都在里面。解析、IP 归一化与域名匹配由 rule 包统一实现
	// （与 client/router 的自定义规则文件共用同一份语义）。
	rules *rule.Set

	// learnedMu 只保护下面两个学习计数：规则集合自己有锁，但"这条是新增的吗"
	// 与"预算还有吗"必须是同一个临界区，否则并发学习会一起越过上限。
	learnedMu      sync.Mutex
	learnedIPs     int
	learnedDomains int
}

func New(proxyURL string, enableUDP, allHost bool) (*NextProxy, error) {
	if proxyURL == "" {
		return nil, nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "socks5" {
		return nil, fmt.Errorf("unsupported next proxy scheme %q", u.Scheme)
	}

	np := &NextProxy{
		url:       u,
		enableUDP: enableUDP,
		allHost:   allHost,
		// 默认值同样只有一个出口：config.NewTimeouts(0) 就是在默认基础超时上
		// 跑一遍派生公式。生产路径随后会用 SetDialTimeout 覆盖它。
		dialTimeout: sharedconfig.NewTimeouts(0).Dial,
		rules:       rule.New(),
	}
	return np, nil
}

func (np *NextProxy) LoadProxyFile(proxyFile string) error {
	if np == nil {
		return nil
	}
	if proxyFile == "" {
		return nil
	}

	set, parseErrs, err := rule.ParseFile(proxyFile, rule.Options{AllowComments: true})
	if err != nil {
		return err
	}
	// 与服务端其它配置错误一致：规则文件里写错的行是**致命**的。客户端路由
	// 那边同样的错误只记启动告警（内置规则仍可工作），但服务端的上游代理列表
	// 一旦缺项，"本该走代理的域名悄悄直连出网"就是一个静默的流量泄漏。
	if err := rule.FileError(proxyFile, parseErrs); err != nil {
		return err
	}
	np.rules = set

	domains, ips, cidrs, patterns := set.Counts()
	log.Info("[NEXTPROXY] loaded proxy file", "file", proxyFile,
		"ips", ips, "cidrs", cidrs, "domains", domains, "patterns", patterns)
	return nil
}

func (np *NextProxy) ShouldProxy(host string) bool {
	if np == nil {
		return false
	}
	if np.allHost {
		return true
	}
	return np.rules.MatchHost(host)
}

// IsCustomDomain 检查域名是否在自定义域名列表中，
// 包括子域名匹配以及 glob/regexp 模式。
func (np *NextProxy) IsCustomDomain(domain string) bool {
	if np == nil {
		return false
	}
	return np.rules.HasDomain(domain)
}

// maxLearnedEntries 限制动态学习的 IP/域名集合的大小：自定义域名的 DNS 响应
// 会在每次查询时喂给 AddIP/AddDomain，长期运行在大型 CDN 池（或记录频繁轮换
// 的域名）之后的服务端若不加限制，这些 map 会无限增长。集合达到上限后学习
// 停止；配置（文件加载）的条目不受影响。
const maxLearnedEntries = 4096

// AddIP 向路由列表中添加一个 IP（线程安全）。学习的 IP 由 rule 包做归一化
// （IPv4-mapped 的 IPv6 折叠为 IPv4），以便与 dial 目标中观测到的字面 IP
// 匹配。超过 maxLearnedEntries 后条目被丢弃，以保持集合有界。
func (np *NextProxy) AddIP(ip string) {
	if np == nil || net.ParseIP(ip) == nil {
		return
	}
	np.learnedMu.Lock()
	defer np.learnedMu.Unlock()
	if np.learnedIPs >= maxLearnedEntries {
		return
	}
	if np.rules.AddIP(ip) {
		np.learnedIPs++
	}
}

// AddDomain 向路由列表中添加一个域名（线程安全）。超过 maxLearnedEntries
// 后条目被丢弃，以保持集合有界。
func (np *NextProxy) AddDomain(domain string) {
	if np == nil {
		return
	}
	np.learnedMu.Lock()
	defer np.learnedMu.Unlock()
	if np.learnedDomains >= maxLearnedEntries {
		return
	}
	if np.rules.AddDomain(domain) {
		np.learnedDomains++
	}
}

// SetDialTimeout 设置拨号连接 SOCKS5 代理的超时时间。它是本类型拨号超时的
// 唯一入口：New 已用默认派生值播种，拨号路径因此不再判断零值（见
// dialSOCKS5Context）。
func (np *NextProxy) SetDialTimeout(d time.Duration) {
	if np == nil {
		return
	}
	np.dialTimeout = d
}

func (np *NextProxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return np.dialSOCKS5Context(ctx, network, addr)
}

// dialSOCKS5Context 经上游 SOCKS5 代理打开一条到 addr 的连接。
//
// 两个 network 走的是两套不同的 SOCKS5 命令，不能共用 x/net/proxy 的拨号器：
//
//   - "tcp" 走 CONNECT，由 x/net/proxy 实现；
//   - "udp" 走 UDP ASSOCIATE（RFC 1928 §7）：先建立到上游的控制连接并协商
//     一次关联，此后每个数据报都按 RSV/FRAG/ATYP/DST.ADDR/DST.PORT 封帧，
//     经上游给出的中继地址转发（见 udpAssociateConn）。
//
// x/net/proxy 只实现 CONNECT，因此把 "udp" 交给它会得到一个必然失败的
// TCP 拨号（"socks connect udp ...: network not implemented"）。这个分支
// 是旧 socks5 客户端库被替换后丢失的能力，见 README 的 next_proxy.enable_udp。
//
// 两条路径都受 ctx 约束：调用方的取消会让进行中的拨号立即中止。
func (np *NextProxy) dialSOCKS5Context(ctx context.Context, network, addr string) (net.Conn, error) {
	if np.url.User != nil {
		log.Info("[NEXTPROXY] connecting via SOCKS5 proxy", "addr", np.url.Host, "network", network, "target", addr)
	} else {
		log.Debug("[NEXTPROXY] connecting via SOCKS5 proxy", "addr", np.url.Host, "network", network, "target", addr)
	}

	// 拨号超时由 New（默认派生值）与 SetDialTimeout（调用方已派生的值）提供，
	// 本路径不再维护第二份默认值：零值意味着"未配置"，会被 ctx 的截止时间或
	// 拨号器自身的默认行为覆盖，而不是悄悄换成另一个数字。
	dialTimeout := np.dialTimeout

	// ctx 的截止时间优先于 np.dialTimeout：DNS 路径传入
	// context.Background()，因此实际生效的一直是后者（与既有的 TCP 路径
	// 一致——拨号侧从不自己取消）。
	dialCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, dialTimeout)
		defer cancel()
	}

	switch network {
	case "udp", "udp4", "udp6":
		conn, err := np.dialUDPAssociate(dialCtx, addr)
		if err != nil {
			return nil, fmt.Errorf("socks5 dial %s: %w", addr, err)
		}
		return conn, nil
	}

	conn, err := np.dialSOCKS5Connect(dialCtx, network, addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial %s: %w", addr, err)
	}
	return conn, nil
}

// dialSOCKS5Connect 是 network=tcp 的路径：x/net/proxy 的 SOCKS5 拨号器
// 实现了 ContextDialer，ctx 在拨号阶段生效并透传给 forward，因此不需要
// "goroutine + 结果 channel + 放弃后排空"的手工取消编排。它的握手本身按 ctx
// 的截止时间设置连接 deadline，并在返回前 defer 清除（见 x/net 的
// internal/socks/client.go），所以旧库 Negotiate() 留下握手 deadline、
// 需要成功后手工清除的那段补偿不再需要——本文件为 udp 路径新建的
// context.WithTimeout/defer cancel() 也是靠这条约定才成立。
//
// 注意它与 UDP 路径在**认证方法通告**上刻意不同：本函数交给 x/net，有凭据时
// 通告 {无认证, 用户名密码} 两个方法；UDP 路径交给 tun2socks 的库，有凭据时
// 只通告 {用户名密码} 一个方法（与迁移前的 socks5 客户端一致）。因此上游若是
// "无需认证、但 URL 里带了凭据"的代理，会出现 TCP 通、UDP 报
// "unsupported method" 的不对称。这是既成行为，不是笔误。
func (np *NextProxy) dialSOCKS5Connect(ctx context.Context, network, addr string, dialTimeout time.Duration) (net.Conn, error) {
	// forward 是 SOCKS5 客户端拨上游代理时使用的底层拨号函数（等价于旧库的
	// c.DialTCP）：只拨上游代理地址，并使用带 Timeout 的 net.Dialer。
	dialer := &net.Dialer{Timeout: dialTimeout}
	forward := socksDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	})

	var auth *xproxy.Auth
	if user, pass, ok := np.credentials(); ok {
		auth = &xproxy.Auth{User: user, Password: pass}
	}
	d, err := xproxy.SOCKS5("tcp", np.url.Host, auth, forward)
	if err != nil {
		return nil, fmt.Errorf("create socks5 dialer: %w", err)
	}
	cd, ok := d.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks5 dialer %T does not support context", d)
	}
	return cd.DialContext(ctx, network, addr)
}

// credentials 返回上游代理的用户名/密码；两者都为空时 ok 为 false（不启用
// 认证协商）。UDP ASSOCIATE 与 CONNECT 共用它，使认证只在 URL 解析一处。
func (np *NextProxy) credentials() (user, password string, ok bool) {
	if np.url == nil || np.url.User == nil {
		return "", "", false
	}
	user = np.url.User.Username()
	password, _ = np.url.User.Password()
	if user == "" && password == "" {
		return "", "", false
	}
	return user, password, true
}

// dialProxyTCP 建立到上游代理的 TCP 连接，并按 dialCtx 的截止时间约束握手。
// 返回的 deadline 是调用方在握手/关联成功后必须清除的绝对时间。
func (np *NextProxy) dialProxyTCP(dialCtx context.Context) (net.Conn, time.Time, error) {
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", np.url.Host)
	if err != nil {
		return nil, time.Time{}, err
	}
	deadline, _ := dialCtx.Deadline()
	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close() //nolint:errcheck
			return nil, time.Time{}, err
		}
	}
	return conn, deadline, nil
}

// socksDialerFunc 是 xproxy.Dialer + ContextDialer 的函数式适配器。它让
// nextproxy 能把"带 Timeout 的 net.Dialer"直接当作 SOCKS5 客户端的底层拨号
// 函数注入，同时保留 ctx 取消能力（net.Dialer.DialContext 原生支持）。
type socksDialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f socksDialerFunc) Dial(network, address string) (net.Conn, error) {
	return f(context.Background(), network, address)
}

func (f socksDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// Host 以 "host:port" 形式返回上游代理地址（nil 接收者时返回 ""）。
// 调用方只需要它用于拨号和日志，因此不暴露内部的 *url.URL。
func (np *NextProxy) Host() string {
	if np == nil || np.url == nil {
		return ""
	}
	return np.url.Host
}

func (np *NextProxy) EnableUDP() bool {
	if np == nil {
		return false
	}
	return np.enableUDP
}
