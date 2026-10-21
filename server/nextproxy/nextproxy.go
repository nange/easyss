package nextproxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/rule"
	xproxy "golang.org/x/net/proxy"
)

type NextProxy struct {
	url         *url.URL
	enableUDP   bool
	allHost     bool
	dialTimeout time.Duration

	// rules 同时承载文件配置与 DNS 学到的条目。用 atomic.Pointer：LoadProxyFile 整体替换集合，
	// 而 ShouldProxy/AddIP/AddDomain 可能在任意 goroutine 上读它。
	rules atomic.Pointer[rule.Set]

	// learnedMu 保护下面两个学习计数："是否新增"与"预算是否还有"必须在同一个临界区，
	// 否则并发学习会一起越过上限。
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
		// 默认值只有 config.NewTimeouts(0) 一个出口，生产路径随后用 SetDialTimeout 覆盖。
		dialTimeout: config.NewTimeouts(0).Dial,
	}
	np.rules.Store(rule.New())
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
	// 规则文件写错的行在服务端是致命的：上游代理列表一旦缺项，"本该走代理的域名悄悄直连出网"
	// 就是静默的流量泄漏。
	if err := rule.FileError(proxyFile, parseErrs); err != nil {
		return err
	}
	np.rules.Store(set)

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
	return np.rules.Load().MatchHost(host)
}

func (np *NextProxy) IsCustomDomain(domain string) bool {
	if np == nil {
		return false
	}
	return np.rules.Load().HasDomain(domain)
}

// maxLearnedEntries 限制动态学习的条目数：DNS 响应会随每次查询喂给 AddIP/AddDomain，跟在大型
// CDN 池之后的服务端不加限制就会无限增长。文件配置的条目不受影响。
const maxLearnedEntries = 4096

func (np *NextProxy) AddIP(ip string) {
	if np == nil || net.ParseIP(ip) == nil {
		return
	}
	np.learnedMu.Lock()
	defer np.learnedMu.Unlock()
	if np.learnedIPs >= maxLearnedEntries {
		return
	}
	if np.rules.Load().AddIP(ip) {
		np.learnedIPs++
	}
}

func (np *NextProxy) AddDomain(domain string) {
	if np == nil {
		return
	}
	np.learnedMu.Lock()
	defer np.learnedMu.Unlock()
	if np.learnedDomains >= maxLearnedEntries {
		return
	}
	if np.rules.Load().AddDomain(domain) {
		np.learnedDomains++
	}
}

// SetDialTimeout 是拨号超时的唯一入口，New 已用默认派生值播种，拨号路径不再判断零值。
func (np *NextProxy) SetDialTimeout(d time.Duration) {
	if np == nil {
		return
	}
	np.dialTimeout = d
}

func (np *NextProxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return np.dialSOCKS5Context(ctx, network, addr)
}

// dialSOCKS5Context 的 "tcp" 走 CONNECT（由 x/net/proxy 实现），"udp" 走 UDP ASSOCIATE
// （见 udpAssociateConn）。
func (np *NextProxy) dialSOCKS5Context(ctx context.Context, network, addr string) (net.Conn, error) {
	if np.url.User != nil {
		log.Info("[NEXTPROXY] connecting via SOCKS5 proxy", "addr", np.url.Host, "network", network, "target", addr)
	} else {
		log.Debug("[NEXTPROXY] connecting via SOCKS5 proxy", "addr", np.url.Host, "network", network, "target", addr)
	}

	dialTimeout := np.dialTimeout

	// ctx 的截止时间优先于 np.dialTimeout：DNS 路径传入 background context，实际生效的
	// 一直是后者。
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

// 认证方法通告与 UDP 路径刻意不同：x/net 有凭据时通告 {无认证，用户名密码}，UDP 路径的库
// 只通告 {用户名密码}，于是"无需认证但 URL 带凭据"的上游会 TCP 通、UDP 报 unsupported method。
func (np *NextProxy) dialSOCKS5Connect(ctx context.Context, network, addr string, dialTimeout time.Duration) (net.Conn, error) {
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

// socksDialerFunc 把带 Timeout 的 net.Dialer 适配成 x/net/proxy 的底层拨号函数。
type socksDialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f socksDialerFunc) Dial(network, address string) (net.Conn, error) {
	return f(context.Background(), network, address)
}

func (f socksDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

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
