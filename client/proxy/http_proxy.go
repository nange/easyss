package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
)

type HTTPProxyServer struct {
	listenAddr string
	handler    *StreamHandler
	router     *router.Router
	method     protocol.Method
	server     *http.Server
	mu         sync.Mutex
}

func NewHTTPProxyServer(listenAddr string, handler *StreamHandler, rt *router.Router, method protocol.Method) *HTTPProxyServer {
	return &HTTPProxyServer{
		listenAddr: listenAddr,
		handler:    handler,
		router:     rt,
		method:     method,
	}
}

func (s *HTTPProxyServer) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("http proxy listen: %w", err)
	}

	log.Info("[HTTP-PROXY] listening", "addr", s.listenAddr)

	httpServer := &http.Server{Handler: http.HandlerFunc(s.serveHTTP)}
	s.mu.Lock()
	s.server = httpServer
	s.mu.Unlock()
	return httpServer.Serve(listener)
}

func (s *HTTPProxyServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	s.handleHTTP(w, r)
}

func (s *HTTPProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}

	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}

	rule := s.router.MatchHostRule(host)
	switch rule {
	case router.HostRuleBlock:
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	case router.HostRuleDirect:
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}

		conn, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		remote, err := net.Dial("tcp", target)
		if err != nil {
			conn.Close()
			return
		}

		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(remote, conn)
			if cw, ok := remote.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()
		go func() {
			defer wg.Done()
			_, _ = io.Copy(conn, remote)
		}()
		wg.Wait()
		conn.Close()
		remote.Close()
		return
	case router.HostRuleProxy:
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}

		conn, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		ctx := context.Background()
		if err := s.handler.OpenTCPStream(ctx, target, s.method, conn); err != nil {
			log.Debug("[HTTP-PROXY] proxy stream", "target", target, "err", err)
			conn.Close()
		}
	}
}

func (s *HTTPProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	rule := s.router.MatchHostRule(host)
	switch rule {
	case router.HostRuleBlock:
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	case router.HostRuleDirect:
		outReq := cloneForRoundTrip(r)
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	case router.HostRuleProxy:
		target := host
		if _, _, err := net.SplitHostPort(host); err != nil {
			if r.URL.Scheme == "https" {
				target = net.JoinHostPort(host, "443")
			} else {
				target = net.JoinHostPort(host, "80")
			}
		}

		s.proxyHTTPRequest(w, r, target)
	}
}

func (s *HTTPProxyServer) proxyHTTPRequest(w http.ResponseWriter, r *http.Request, target string) {
	clientConn, handlerConn := net.Pipe()
	defer clientConn.Close()

	streamErr := make(chan error, 1)
	go func() {
		streamErr <- s.handler.OpenTCPStream(context.Background(), target, s.method, handlerConn)
	}()

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- cloneForOrigin(r).Write(clientConn)
	}()

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), r)
	if err != nil {
		clientConn.Close()
		select {
		case err := <-streamErr:
			if err != nil {
				log.Debug("[HTTP-PROXY] proxy stream", "target", target, "err", err)
			}
		default:
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	select {
	case err := <-writeErr:
		if err != nil {
			log.Debug("[HTTP-PROXY] write request", "target", target, "err", err)
		}
	default:
	}

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func cloneForOrigin(r *http.Request) *http.Request {
	out := r.Clone(r.Context())
	u := *out.URL
	u.Scheme = ""
	u.Host = ""
	out.URL = &u
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	out.Header.Del("Proxy-Connection")
	return out
}

func cloneForRoundTrip(r *http.Request) *http.Request {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	if out.URL.Host == "" {
		out.URL.Host = r.Host
	}
	out.Header = r.Header.Clone()
	out.Header.Del("Proxy-Connection")
	return out
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
