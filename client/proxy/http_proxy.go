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

	// TUN helper support (macOS): config served at GET /tun.
	tunCfg *TunConfig
	tunMu  sync.RWMutex
}

// TunConfig is the configuration served to the TUN helper via GET /tun.
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

func NewHTTPProxyServer(listenAddr, socksAddr, username, password string, timeout time.Duration, handler *StreamHandler, rt *router.Router, method protocol.Method, dial func(context.Context, string, string) (net.Conn, error)) (*HTTPProxyServer, error) {
	if socksAddr == "" {
		return nil, fmt.Errorf("http proxy requires a local socks5 address")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if dial == nil {
		dial = defaultDirectDialContext
	}

	socksURL := &url.URL{Scheme: "socks5", Host: socksAddr}
	if username != "" || password != "" {
		socksURL.User = url.UserPassword(username, password)
	}

	s := &HTTPProxyServer{
		listenAddr: listenAddr,
		socksAddr:  socksAddr,
		socksURL:   socksURL,
		username:   username,
		password:   password,
		timeout:    timeout,
		handler:    handler,
		router:     rt,
		method:     method,
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
	if !s.authOK(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Easyss"`)
		http.Error(w, "Proxy auth required", http.StatusProxyAuthRequired)
		return
	}

	// Serve /stats for direct requests to the proxy.
	if r.URL.Host == "" && r.URL.Path == "/stats" {
		s.serveStats(w)
		return
	}

	// Serve /tun for TUN configuration (macOS helper).
	if r.URL.Host == "" && r.URL.Path == "/tun" {
		if r.Method == http.MethodGet {
			s.handleTunGET(w)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// Prevent forwarding loops: reject requests that would be forwarded
	// back to the proxy itself (both relative and absolute URLs).
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

// SetTunConfig stores the TUN configuration served at GET /tun.
// Called before spawning the TUN helper on macOS.
func (s *HTTPProxyServer) SetTunConfig(cfg *TunConfig) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	s.tunCfg = cfg
}

// ClearTunConfig removes the TUN configuration. Called after the TUN helper exits.
func (s *HTTPProxyServer) ClearTunConfig() {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	s.tunCfg = nil
}

// handleTunGET serves the TUN configuration as JSON.
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

// isSelfTarget reports whether r would be forwarded back to the proxy itself,
// which would cause an infinite forwarding loop.
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
		// Never resolve domain names here: the lookup would go through the
		// proxied DNS path and could deadlock or recurse.
		return false
	}
	_, local := localIPSet()[ip.String()]
	return ip.IsLoopback() || local
}

const localIPsCacheTTL = 60 * time.Second

var localIPsCache = struct {
	sync.Mutex
	updated time.Time
	set     map[string]struct{}
}{}

// localIPSet returns the set of IP addresses currently assigned to local
// interfaces, cached for localIPsCacheTTL. It detects requests targeting the
// proxy host itself: when listening on [::]:port, a request to a LAN address
// of this host (e.g. 192.168.1.5:port) would otherwise be tunneled to the
// server and potentially loop back into this proxy, creating an infinite
// forwarding loop.
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

	rule := router.HostRuleProxy
	if s.router != nil {
		rule = s.router.MatchHostRule(host)
	}
	if rule == router.HostRuleBlock {
		log.Info("[HTTP-PROXY] CONNECT blocked", "target", target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	rc := http.NewResponseController(w)
	hijConn, _, err := rc.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error("[HTTP-PROXY] hijack CONNECT", "target", target, "err", err)
		return
	}
	defer hijConn.Close() //nolint:errcheck

	if rule == router.HostRuleDirect {
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
		relayTCP(remote, hijConn)
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
		relayTCP(remote, hijConn)
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
	client, err := socks5.NewClient(s.socksAddr, s.username, s.password, int(s.timeout.Seconds()), int(s.timeout.Seconds()))
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
	username, password, ok = r.BasicAuth()
	if ok {
		return username, password, true
	}
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", false
	}
	return parseBasicAuth(auth)
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
