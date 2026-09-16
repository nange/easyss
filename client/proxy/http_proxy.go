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
	router     *router.Router
	method     protocol.Method
	dial       func(context.Context, string, string) (net.Conn, error)
	rp         *httputil.ReverseProxy
	server     *http.Server
	mu         sync.Mutex

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
type HTTPProxyOptions struct {
	ListenAddr string
	SocksAddr  string
	Username   string
	Password   string
	// Timeout 是反向代理出站请求与空闲处理所用的基础超时。
	Timeout time.Duration
	Handler *StreamHandler
	Router  *router.Router
	Method  protocol.Method
	// Dial 在路由把主机标记为直连时为转发路径打开直连连接（绕过本地 SOCKS5 代理）；
	// 为 nil 时使用普通的 net.Dialer。
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
		router:     opts.Router,
		method:     opts.Method,
		dial:       dial,
	}
	s.rp = s.newReverseProxy()
	return s, nil
}

func (s *HTTPProxyServer) newReverseProxy() *httputil.ReverseProxy {
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
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return s.socksURL, nil
			},
			TLSHandshakeTimeout: s.timeout / 3,
		},
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

	log.Info("[HTTP-PROXY] listening", "addr", s.listenAddr, "socks5", s.socksURL.Redacted())

	httpServer := &http.Server{Handler: s}
	s.mu.Lock()
	s.server = httpServer
	s.mu.Unlock()
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

	// IPv6 策略门禁与路由规则来自与 SOCKS5 路径共享的同一个分类结果，
	// 因此两个入口不会发生偏离。
	cls := s.router.ClassifyHost(host)
	if cls.IPV6Rejected {
		log.Warn("[HTTP-PROXY] CONNECT ipv6 target rejected, ipv6 disabled", "target", target)
		http.Error(w, "IPv6 disabled", http.StatusForbidden)
		return
	}
	if cls.Rule == router.HostRuleBlock {
		log.Info("[HTTP-PROXY] CONNECT blocked", "target", target)
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

	if cls.Rule == router.HostRuleDirect {
		log.Info("[HTTP-PROXY] CONNECT direct", "target", target)
		remote, err := s.directConnect(target)
		if err != nil {
			log.Warn("[HTTP-PROXY] direct CONNECT", "target", target, "err", err)
			return
		}
		defer remote.Close() //nolint:errcheck
		if err := writeConnectEstablished(hijConn, target); err != nil {
			return
		}
		relayTCP(remote, hijConn, config.StreamIdleTimeout(s.timeout))
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
		relayTCP(remote, hijConn, config.StreamIdleTimeout(s.timeout))
		return
	}

	if err := writeConnectEstablished(hijConn, target); err != nil {
		return
	}
	log.Info("[HTTP-PROXY] CONNECT proxy", "target", target)
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

func (s *HTTPProxyServer) directConnect(target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	return s.dial(ctx, "tcp", target)
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

func (s *HTTPProxyServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}
