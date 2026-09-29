package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/txthinking/socks5"
)

type reverseProxyBufferPool struct{}

func (reverseProxyBufferPool) Get() []byte {
	return bytespool.Get(config.TCPStreamBufferSize)
}

func (reverseProxyBufferPool) Put(buf []byte) {
	bytespool.MustPut(buf)
}

type HTTPProxyServer struct {
	listenAddr string
	socksAddr  string
	socksURL   *url.URL
	username   string
	password   string
	timeout    time.Duration
	handler    *StreamHandler
	// policy 与 SOCKS5 入口共用同一套 Block/Direct/Proxy 判定（见 route.go），
	// 也是本入口唯一的路由规则持有者。
	policy *routePolicy
	method protocol.Method
	dial   func(context.Context, string, string) (net.Conn, error)
	rp     *httputil.ReverseProxy
	// rpTransport 是反向代理（普通 HTTP 转发）自己的连接池：它拨的是本地 SOCKS5
	// 入口，池中的空闲连接会连带占住 SOCKS5 侧的 handler goroutine 与一条隧道流，
	// 因此 Close 必须回收它，而不能只关监听器（见 Close）。
	rpTransport *http.Transport
	server      *http.Server
	// listener 在 Start 中被登记，供 Close 释放；Close 早于 Start 时 server 为 nil。
	listener net.Listener
	// closing 由 Close 在 mu 下置位。Start 会在登记监听器之前检查它：runner 在
	// goroutine 中启动服务器，核心可能随即被停止，此时迟到的 Start 必须自己关掉
	// 监听器，否则端口会被一个无人引用的服务器永久占用（重启会因端口被占而失败）。
	closing bool
	mu      sync.Mutex

	// TUN 辅助程序支持（darwin/linux）：配置通过 GET /tun 提供。
	tunCfg *TunConfig
	tunMu  sync.RWMutex
}

// TunConfig 是通过 GET /tun 提供给 TUN 辅助程序的配置。
type TunConfig struct {
	Socks5Addr     string `json:"socks5_addr"`
	DNSAddr        string `json:"dns_addr"`
	Device         string `json:"device"`
	TunIP          string `json:"tun_ip"`
	TunGW          string `json:"tun_gw"`
	TunMask        string `json:"tun_mask"`
	TunIPV6Sub     string `json:"tun_ipv6_sub,omitempty"`
	TunGWV6        string `json:"tun_gwv6,omitempty"`
	ServerIPV6     string `json:"server_ipv6,omitempty"`
	LocalGateway   string `json:"local_gateway"`
	LocalGatewayV6 string `json:"local_gateway_v6,omitempty"`
	MTU            int    `json:"mtu"`
}

// HTTPProxyOptions 用于配置 NewHTTPProxyServer。它取代了一个已增长到九个参数的
// 位置参数列表。
//
// 字段的所有权约定（Close 只关闭本类型自己创建的东西）：
//   - Handler/Router/Dial 一律**借用**：调用方持有它们，并与 SOCKS5 入口共用
//     （见 Socks5Options），Close 绝不关闭它们；
//   - SocksAddr 指向的本地 SOCKS5 入口由调用方持有，本类型只拨它，不关它
//     ——因此关闭顺序必须是"先本入口、后 SOCKS5"（见 runner.Core.cleanup）；
//   - 服务器自己创建并负责关闭的是监听器与反向代理的连接池（见 Close）。
type HTTPProxyOptions struct {
	ListenAddr string
	SocksAddr  string
	Username   string
	Password   string
	// Timeout 是反向代理出站请求与空闲处理所用的基础超时。
	Timeout time.Duration
	// Handler 是借用的隧道流处理器（由 runner 创建并与 SOCKS5 入口共用）。
	Handler *StreamHandler
	// Router 是借用的路由引擎（同样与 SOCKS5 入口共用）。
	Router *router.Router
	Method protocol.Method
	// Dial 在路由把主机标记为直连时为转发路径打开直连连接（绕过本地 SOCKS5 代理）；
	// 为 nil 时使用普通的 net.Dialer。它同样是借用的函数值。
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewHTTPProxyServer(opts HTTPProxyOptions) (*HTTPProxyServer, error) {
	listenAddr, socksAddr := opts.ListenAddr, opts.SocksAddr
	if socksAddr == "" {
		return nil, fmt.Errorf("http proxy requires a local socks5 address")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeout) * time.Second
	}
	dial := opts.Dial
	if dial == nil {
		dial = defaultDirectDialContext
	}

	socksURL := &url.URL{Scheme: "socks5", Host: socksAddr}
	if opts.Username != "" || opts.Password != "" {
		socksURL.User = url.UserPassword(opts.Username, opts.Password)
	}

	s := &HTTPProxyServer{
		listenAddr: listenAddr,
		socksAddr:  socksAddr,
		socksURL:   socksURL,
		username:   opts.Username,
		password:   opts.Password,
		timeout:    timeout,
		handler:    opts.Handler,
		method:     opts.Method,
		dial:       dial,
	}
	// 中继空闲超时与 SOCKS5 入口同源（config.StreamIdleTimeout 是唯一事实来源），
	// 只是本入口持有的是基础超时而非派生值。
	s.policy = newRoutePolicy(routePolicyOptions{
		Router:            opts.Router,
		Dial:              dial,
		DialTimeout:       timeout,
		StreamIdleTimeout: config.StreamIdleTimeout(timeout),
	})
	s.rp = s.newReverseProxy()
	return s, nil
}

func (s *HTTPProxyServer) newReverseProxy() *httputil.ReverseProxy {
	// 连接池在这里创建、由 HTTPProxyServer 持有：Close 需要回收它的空闲连接
	// （见 HTTPProxyServer.Close）。
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return s.socksURL, nil
		},
		TLSHandshakeTimeout: s.timeout / 3,
	}
	s.rpTransport = tr

	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			if pr.Out.URL.Scheme == "" {
				pr.Out.URL.Scheme = "http"
			}
			if pr.Out.URL.Host == "" {
				pr.Out.URL.Host = pr.In.Host
			}
			pr.Out.Host = pr.Out.URL.Host
			pr.Out.RequestURI = ""
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		Transport:  tr,
		BufferPool: reverseProxyBufferPool{},
		ErrorHandler: func(rw http.ResponseWriter, r *http.Request, err error) {
			log.Warn("[HTTP-PROXY] reverse proxy request", "err", err)
			http.Error(rw, "Service unavailable", http.StatusServiceUnavailable)
		},
	}
}

// Start 绑定监听地址并开始服务。Close 先于 Start 发生时，迟到的 Start 会关掉
// 自己刚绑定的监听器并返回 http.ErrServerClosed，而不是让一个无人引用的服务器
// 永久占用端口（调用方已把该错误视为正常停止，见 runner 的错误过滤）。
func (s *HTTPProxyServer) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("http proxy listen: %w", err)
	}

	httpServer := &http.Server{Handler: s}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = listener.Close()
		return http.ErrServerClosed
	}
	s.listener = listener
	s.server = httpServer
	s.mu.Unlock()

	log.Info("[HTTP-PROXY] listening", "addr", s.listenAddr, "socks5", s.socksURL.Redacted())

	return httpServer.Serve(listener)
}

func (s *HTTPProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 在代理认证检查之前提供 /tun：提权的 TUN 辅助程序（darwin/linux）无需凭据
	// 即可获取其配置。该端点被限制为仅接受回环来源，因此当代理监听所有接口
	// （bind_all）时，配置也不会暴露到网络上。
	if r.URL.Host == "" && r.URL.Path == "/tun" {
		if !isLoopbackRequest(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			s.handleTunGET(w)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if !s.authOK(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Easyss"`)
		http.Error(w, "Proxy auth required", http.StatusProxyAuthRequired)
		return
	}

	// 为直接发往代理的请求提供 /stats。
	if r.URL.Host == "" && r.URL.Path == "/stats" {
		s.serveStats(w)
		return
	}

	// 防止转发环路：拒绝会被转发回代理自身的请求（包括相对与绝对 URL）。
	if s.isSelfTarget(r) {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	log.Info("[HTTP-PROXY] forwarding via SOCKS5", "host", r.Host, "method", r.Method)
	s.rp.ServeHTTP(w, r)
}

func (s *HTTPProxyServer) serveStats(w http.ResponseWriter) {
	snap := stats.Collect()
	snap.TransportStats = s.handler.Transport().Stats()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snap); err != nil {
		log.Warn("[HTTP-PROXY] encode stats", "err", err)
	}
}

// SetTunConfig 存储通过 GET /tun 提供的 TUN 配置。
// 在 darwin/linux 上启动 TUN 辅助程序之前调用。
func (s *HTTPProxyServer) SetTunConfig(cfg *TunConfig) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	s.tunCfg = cfg
}

// ClearTunConfig 移除 TUN 配置。在 TUN 辅助程序退出后调用。
func (s *HTTPProxyServer) ClearTunConfig() {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	s.tunCfg = nil
}

// handleTunGET 以 JSON 形式提供 TUN 配置。
func (s *HTTPProxyServer) handleTunGET(w http.ResponseWriter) {
	s.tunMu.RLock()
	cfg := s.tunCfg
	s.tunMu.RUnlock()

	if cfg == nil {
		http.Error(w, "TUN not configured", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(cfg); err != nil {
		log.Warn("[HTTP-PROXY] encode tun config", "err", err)
	}
}

// isSelfTarget 报告 r 是否会被转发回代理自身，从而造成无限的转发环路。
func (s *HTTPProxyServer) isSelfTarget(r *http.Request) bool {
	target := r.URL.Host
	if target == "" {
		target = r.Host
	}
	if target == s.listenAddr {
		return true
	}
	th, tp, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	_, lp, err := net.SplitHostPort(s.listenAddr)
	if err != nil {
		return false
	}
	if tp != lp {
		return false
	}
	if th == "localhost" {
		return true
	}
	ip := net.ParseIP(th)
	if ip == nil {
		// 这里绝不解析域名：解析会走代理 DNS 路径，可能导致死锁或递归。
		return false
	}
	_, local := localIPSet()[ip.String()]
	return ip.IsLoopback() || local
}

// isLoopbackRequest 报告请求是否来自回环地址（本机自身）。它保护控制端点（例如
// GET /tun），即使代理监听所有接口，这些端点也只能从本机访问。
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

const localIPsCacheTTL = 60 * time.Second

var localIPsCache = struct {
	sync.Mutex
	updated time.Time
	set     map[string]struct{}
}{}

// localIPSet 返回当前分配给本地接口的 IP 地址集合，按 localIPsCacheTTL 缓存。
// 它用于识别目标是代理主机自身的请求：当监听 [::]:port 时，指向本机局域网地址
// （例如 192.168.1.5:port）的请求本来会被隧道转发到服务器，并可能回环进入本代理，
// 形成无限的转发环路。
func localIPSet() map[string]struct{} {
	localIPsCache.Lock()
	defer localIPsCache.Unlock()
	if time.Since(localIPsCache.updated) < localIPsCacheTTL && localIPsCache.set != nil {
		return localIPsCache.set
	}
	set := make(map[string]struct{})
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil {
					set[ip.String()] = struct{}{}
				}
			}
		}
	}
	localIPsCache.set = set
	localIPsCache.updated = time.Now()
	return set
}

func (s *HTTPProxyServer) authOK(r *http.Request) bool {
	if s.username == "" && s.password == "" {
		return true
	}
	username, password, ok := basicAuth(r)
	return ok && username == s.username && password == s.password
}

func (s *HTTPProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := connectTarget(r)
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		http.Error(w, "Bad CONNECT target", http.StatusBadRequest)
		return
	}

	// IPv6 策略门禁与路由规则来自与 SOCKS5 路径共享的同一个 routePolicy，
	// 因此两个入口不会发生偏离（见 route.go）。
	decision := s.policy.decide(host)
	if decision.IPV6Rejected {
		logRouteIPV6Rejected("[HTTP-PROXY]", target)
		http.Error(w, "IPv6 disabled", http.StatusForbidden)
		return
	}
	logRouteDecision("[HTTP-PROXY]", decision, host, target, r.RemoteAddr)
	if decision.Action == routeBlock {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	rc := http.NewResponseController(w)
	hijConn, _, err := rc.Hijack()
	if err != nil {
		// 绝不把内部错误回显给客户端：它可能向远端调用者泄露本地细节
		// （接口名、文件描述符）。
		http.Error(w, "CONNECT failed", http.StatusInternalServerError)
		log.Error("[HTTP-PROXY] hijack CONNECT", "target", target, "err", err)
		return
	}
	defer hijConn.Close() //nolint:errcheck

	if decision.Action == routeDirect {
		remote, err := s.policy.dialDirect(target)
		if err != nil {
			log.Warn("[HTTP-PROXY] direct CONNECT", "target", target, "err", err)
			return
		}
		defer remote.Close() //nolint:errcheck
		if err := writeConnectEstablished(hijConn, target); err != nil {
			return
		}
		relayTCP(remote, hijConn, s.policy.streamIdle())
		return
	}

	if s.handler == nil {
		log.Info("[HTTP-PROXY] CONNECT via SOCKS5 (no handler)", "target", target)
		remote, err := s.dialSOCKS5(target)
		if err != nil {
			log.Warn("[HTTP-PROXY] socks5 CONNECT", "target", target, "err", err)
			return
		}
		defer remote.Close() //nolint:errcheck
		if err := writeConnectEstablished(hijConn, target); err != nil {
			return
		}
		relayTCP(remote, hijConn, s.policy.streamIdle())
		return
	}

	if err := writeConnectEstablished(hijConn, target); err != nil {
		return
	}
	if err := s.handler.OpenTCPStream(context.Background(), target, s.method, hijConn); err != nil {
		if isTransientStreamError(err) {
			log.Debug("[HTTP-PROXY] CONNECT closed", "target", target, "err", err)
			return
		}
		log.Warn("[HTTP-PROXY] CONNECT stream", "target", target, "err", err)
	}
}

func writeConnectEstablished(conn net.Conn, target string) error {
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Warn("[HTTP-PROXY] write CONNECT response", "target", target, "err", err)
		return err
	}
	return nil
}

func (s *HTTPProxyServer) dialSOCKS5(target string) (net.Conn, error) {
	// 将超时向上取整，避免亚秒级超时被截断为 0（socks5 库把 0 视为"无超时"）。
	socksTimeout := max(int(math.Ceil(s.timeout.Seconds())), 1)
	client, err := socks5.NewClient(s.socksAddr, s.username, s.password, socksTimeout, socksTimeout)
	if err != nil {
		return nil, err
	}
	return client.Dial("tcp", target)
}

func connectTarget(r *http.Request) string {
	target := r.URL.Host
	if target == "" {
		target = r.Host
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	return target
}

func basicAuth(r *http.Request) (username, password string, ok bool) {
	// 代理凭据放在 Proxy-Authorization 头中；仅当该头缺失时才回退到
	// Authorization 头，这样同时携带两者的客户端（一个发给源站的 Authorization 头
	// 连同代理自己的凭据）不会被误拒。
	auth := r.Header.Get("Proxy-Authorization")
	if auth != "" {
		return parseBasicAuth(auth)
	}
	username, password, ok = r.BasicAuth()
	return username, password, ok
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	username, password, ok = strings.Cut(string(decoded), ":")
	return username, password, ok
}

// Close 关闭本服务器持有的全部资源：HTTP 监听器与在飞请求，以及反向代理自己的
// 连接池（它拨本地 SOCKS5 入口，空闲连接会连带占住一条隧道流）。
//
// 它刻意不关闭借用的依赖：handler（StreamHandler）、policy/router、dial 与
// method 都由 runner 持有并与 SOCKS5 入口共用（见 HTTPProxyOptions 的字段注释）
// —— 关闭它们需要由持有者（runner.Core）按逆序统一编排。
//
// 幂等：重复调用不会再次 Shutdown，也不会让迟到的 Start 重新上线（见 Start）。
func (s *HTTPProxyServer) Close() error {
	s.mu.Lock()
	alreadyClosed := s.closing
	s.closing = true
	srv := s.server
	s.mu.Unlock()

	var shutdownErr error
	if srv != nil && !alreadyClosed {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr = srv.Shutdown(ctx)
	}
	// 连接池无条件回收：即便优雅关闭超时（在飞请求没有在预算内结束），
	// 空闲连接也必须释放——它们各自占着一条隧道流。
	if s.rpTransport != nil {
		s.rpTransport.CloseIdleConnections()
	}
	return shutdownErr
}
