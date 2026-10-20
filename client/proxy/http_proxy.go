package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	xproxy "golang.org/x/net/proxy"
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
	timeouts   config.Timeouts
	handler    *StreamHandler
	// policy 与 SOCKS5 入口共用同一套 Block/Direct/Proxy 判定。
	policy *routePolicy
	method protocol.Method
	dial   func(context.Context, string, string) (net.Conn, error)
	rp     *httputil.ReverseProxy
	// rpTransport 是反向代理自己的连接池：空闲连接会占住一条隧道流，Close 必须回收它。
	rpTransport *http.Transport
	// server 是 Close 唯一的释放入口：Shutdown 关闭 Serve 注册过的监听器。
	server *http.Server
	// closing 由 Close 在 mu 下置位。Serve 在登记 server 之前检查它：核心可能在启动 goroutine
	// 之后随即被停止，迟到的 Serve 必须自己关掉监听器，否则端口会被永久占用。
	closing bool
	mu      sync.Mutex

	tunCfg *TunConfig
	tunMu  sync.RWMutex
}

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

// HTTPProxyOptions 用于配置 NewHTTPProxyServer。Handler/Router/Dial 一律借用（与 SOCKS5 入口
// 共用），SocksAddr 指向的本地 SOCKS5 入口由调用方持有，因此关闭顺序是先本入口、后 SOCKS5。
type HTTPProxyOptions struct {
	ListenAddr string
	SocksAddr  string
	Username   string
	Password   string
	// Timeouts 与 SOCKS5 入口共用同一份派生超时集合，各派生会让同一个直连目标超时不同。
	Timeouts config.Timeouts
	Handler  *StreamHandler
	Router   *router.Router
	Method   protocol.Method
	// Dial 为直连分支打开连接（绕过本地 SOCKS5 代理）；为 nil 时使用普通 net.Dialer。
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewHTTPProxyServer(opts HTTPProxyOptions) (*HTTPProxyServer, error) {
	listenAddr, socksAddr := opts.ListenAddr, opts.SocksAddr
	if socksAddr == "" {
		return nil, fmt.Errorf("http proxy requires a local socks5 address")
	}
	timeouts := opts.Timeouts.Normalize()
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
		timeouts:   timeouts,
		handler:    opts.Handler,
		method:     opts.Method,
		dial:       dial,
	}
	s.policy = newRoutePolicy(routePolicyOptions{
		Router:            opts.Router,
		Dial:              dial,
		DialTimeout:       timeouts.Dial,
		StreamIdleTimeout: timeouts.StreamIdle,
	})
	s.rp = s.newReverseProxy()
	return s, nil
}

func (s *HTTPProxyServer) newReverseProxy() *httputil.ReverseProxy {
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return s.socksURL, nil
		},
		// 握手超时沿用同一个派生值。
		TLSHandshakeTimeout: s.timeouts.Dial,
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

func (s *HTTPProxyServer) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("http proxy listen: %w", err)
	}
	return s.Serve(listener)
}

// Serve 在调用方提供的监听器上服务，所有权转移给本服务器。Close 先于 Serve 时，迟到的 Serve
// 会关掉监听器并返回 http.ErrServerClosed，而不是永久占用端口。
func (s *HTTPProxyServer) Serve(listener net.Listener) error {
	httpServer := &http.Server{Handler: s}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = listener.Close()
		return http.ErrServerClosed
	}
	s.server = httpServer
	s.mu.Unlock()

	log.Info("[HTTP-PROXY] listening", "addr", listener.Addr().String(), "socks5", s.socksURL.Redacted())

	return httpServer.Serve(listener)
}

func (s *HTTPProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /tun 在认证之前提供（提权的 TUN 辅助程序没有凭据），只接受回环来源，因此在 bind_all
	// 时也不会暴露到网络上。
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

	if r.URL.Host == "" && r.URL.Path == "/stats" {
		s.serveStats(w)
		return
	}

	// 防止转发环路：拒绝会被转发回代理自身的请求（含相对与绝对 URL）。
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

func (s *HTTPProxyServer) SetTunConfig(cfg *TunConfig) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	s.tunCfg = cfg
}

func (s *HTTPProxyServer) ClearTunConfig() {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	s.tunCfg = nil
}

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
		// 绝不解析域名：解析会走代理 DNS 路径，可能导致死锁或递归。
		return false
	}
	_, local := localIPSet()[ip.String()]
	return ip.IsLoopback() || local
}

// isLoopbackRequest 保护控制端点（如 GET /tun）：即使代理监听所有接口，它们也只能从本机访问。
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

// localIPSet 返回本地接口的 IP 集合（按 localIPsCacheTTL 缓存），用于识别目标是代理主机自身的
// 请求：监听 [::]:port 时这类请求会被隧道转发到服务器并可能回环回本代理。
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

	// IPv6 门禁与路由规则来自与 SOCKS5 路径共享的同一个 routePolicy。
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
		// 绝不把内部错误回显给客户端：它会泄露本地细节（接口名、文件描述符）。
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
	var auth *xproxy.Auth
	if s.username != "" || s.password != "" {
		auth = &xproxy.Auth{User: s.username, Password: s.password}
	}

	// 拨本地 SOCKS5 入口也是一次出站拨号，与直连拨号共用 Dial 超时。
	forward := &socksForwardDialer{timeout: s.timeouts.Dial}
	d, err := xproxy.SOCKS5("tcp", s.socksAddr, auth, forward)
	if err != nil {
		return nil, err
	}
	cd, ok := d.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks5 dialer %T does not support context", d)
	}
	conn, err := cd.DialContext(context.Background(), "tcp", target)
	if err != nil {
		return nil, err
	}
	return &socksHalfCloser{Conn: conn, raw: forward.lastConn()}, nil
}

// socksForwardDialer 把每次成功建立的裸连接记在 conn 里，供上层还原底层 *net.TCPConn：库返回
// 的 SOCKS5 连接不实现 CloseWrite，而中继在干净 EOF 时依赖它。
type socksForwardDialer struct {
	timeout time.Duration

	mu   sync.Mutex
	conn net.Conn
}

func (f *socksForwardDialer) Dial(network, address string) (net.Conn, error) {
	return f.DialContext(context.Background(), network, address)
}

func (f *socksForwardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: f.timeout}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.conn = conn
	f.mu.Unlock()
	return conn, nil
}

func (f *socksForwardDialer) lastConn() net.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conn
}

// socksHalfCloser 为 SOCKS5 客户端连接补上 CloseWrite：协商完成后裸 TCP 连接仍是同一个，因此
// 能断言回 *net.TCPConn 让半关闭像直连路径一样传播。
type socksHalfCloser struct {
	net.Conn
	raw net.Conn
}

func (c *socksHalfCloser) CloseWrite() error {
	if tc, ok := c.raw.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	log.Debug("[HTTP-PROXY] SOCKS5 half-close unavailable, skipping", "raw", fmt.Sprintf("%T", c.raw))
	return nil
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
	// 代理凭据在 Proxy-Authorization 头中，只有它缺失时才回退到 Authorization，这样同时携带
	// 两者的客户端（发往源站的 Authorization 加代理凭据）不会被误拒。
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

// Close 关闭监听器与在飞请求，以及反向代理自己的连接池（空闲连接会连带占住一条隧道流）。
// 借用的 handler、policy/router 与 dial 由持有者按逆序统一编排。
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
	// 连接池无条件回收：即便优雅关闭超时，空闲连接也必须释放——它们各自占着一条隧道流。
	if s.rpTransport != nil {
		s.rpTransport.CloseIdleConnections()
	}
	return shutdownErr
}
