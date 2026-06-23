package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// statsResponse wraps Snapshot with derived fields for JSON output.
type statsResponse struct {
	stats.Snapshot
	UptimeSeconds float64 `json:"uptime_seconds"`
	ActiveStreams int64   `json:"active_streams"`
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
	resp := statsResponse{
		Snapshot:      snap,
		UptimeSeconds: snap.Uptime().Seconds(),
		ActiveStreams: snap.ActiveStreams(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Warn("[HTTP-PROXY] encode stats", "err", err)
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
	// Handle localhost aliases (e.g. 127.0.0.1 vs localhost vs ::1).
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
	return th == "127.0.0.1" || th == "localhost" || th == "::1"
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
		if errors.Is(err, ErrStreamIdleTimeout) {
			log.Debug("[HTTP-PROXY] CONNECT idle closed", "target", target, "err", err)
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
