package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util"
	"github.com/txthinking/socks5"

	easydns "github.com/nange/easyss/v3/client/dns"
)

type Socks5Server struct {
	srv *socks5.Server

	handler           *StreamHandler
	router            *router.Router
	dnsCache          *easydns.Cache
	serverDomain      string
	method            protocol.Method
	disableQUIC       bool
	directDialContext func(context.Context, string, string) (net.Conn, error)
	dialTimeout       time.Duration

	udpMu          sync.RWMutex
	udpExch        map[string]*UDPExchange
	udpInflight    map[string]*udpExchangeFactory
	directUDP      map[string]net.Conn
	quit           chan struct{}
	closeOnce      sync.Once
	udpIdleTimeout time.Duration
	started        atomic.Bool
}

func NewSocks5Server(listenAddr, username, password string, handler *StreamHandler, rt *router.Router, serverDomain string, method protocol.Method, disableQUIC bool, dialTimeout, udpIdleTimeout time.Duration, directDialContext func(context.Context, string, string) (net.Conn, error)) (*Socks5Server, error) {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	if udpIdleTimeout <= 0 {
		udpIdleTimeout = 30 * time.Second
	}
	if directDialContext == nil {
		directDialContext = defaultDirectDialContext
	}
	if net.ParseIP(serverDomain) != nil {
		serverDomain = ""
	}
	s := &Socks5Server{
		handler:           handler,
		router:            rt,
		dnsCache:          easydns.NewCache(),
		serverDomain:      serverDomain,
		method:            method,
		disableQUIC:       disableQUIC,
		directDialContext: directDialContext,
		dialTimeout:       dialTimeout,
		udpExch:           make(map[string]*UDPExchange),
		udpInflight:       make(map[string]*udpExchangeFactory),
		directUDP:         make(map[string]net.Conn),
		quit:              make(chan struct{}),
		udpIdleTimeout:    udpIdleTimeout,
	}
	srv, err := socks5.NewClassicServer(listenAddr, "127.0.0.1", username, password, 0, 0)
	if err != nil {
		return nil, err
	}
	s.srv = srv
	return s, nil
}

func defaultDirectDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

// PrePopulateDNS pre-seeds the DNS cache with the resolved IPs for the
// given domain. This avoids a DNS deadlock when TUN routes are active.
func (s *Socks5Server) PrePopulateDNS(domain, dnsServer string, requireIPv4 bool) error {
	return s.dnsCache.PrePopulate(domain, dnsServer, requireIPv4)
}

// isServerDomain reports whether the given domain is the proxy server's own
// hostname. DNS queries for it must never take the proxied path: resolving
// the server domain would require opening a tunnel stream, which in turn
// needs to dial the server domain — a circular dependency that deadlocks
// (especially after system sleep/wake when cached entries may have expired).
func (s *Socks5Server) isServerDomain(domain string) bool {
	return s.serverDomain != "" && strings.EqualFold(domain, s.serverDomain)
}

// MarkStarted records that Start is about to be called. It must be called
// synchronously before launching Start in a goroutine: the flag set inside
// Start itself would race with a Close on a single-core scheduler, letting
// the server goroutine leak its listener.
func (s *Socks5Server) MarkStarted() {
	s.started.Store(true)
}

func (s *Socks5Server) Start() error {
	s.started.Store(true)
	go s.cleanupLoop()
	return s.srv.ListenAndServe(s)
}

// waitForAccept polls the listen address until the server has started
// accepting connections. Shutting down before the accept loop is up
// deadlocks inside the txthinking/socks5 runnergroup library, so Close
// must never race with the goroutine spawned by Start.
func (s *Socks5Server) waitForAccept() {
	if s.srv == nil {
		return
	}
	addr := s.srv.Addr
	if addr == "" {
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *Socks5Server) Close() error {
	s.closeOnce.Do(func() { close(s.quit) })
	if s.started.Load() {
		s.waitForAccept()
	}
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	for key, ue := range s.udpExch {
		ue.Close() //nolint:errcheck
		delete(s.udpExch, key)
	}
	for key, conn := range s.directUDP {
		conn.Close() //nolint:errcheck
		delete(s.directUDP, key)
	}
	if s.srv != nil {
		return s.srv.Shutdown()
	}
	return nil
}

func (s *Socks5Server) TCPHandle(srv *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdUDP {
		caddr, err := r.UDP(c, srv.ServerAddr)
		if err != nil {
			log.Error("[SOCKS5] udp associate failed", "client", c.RemoteAddr().String(), "err", err)
			return err
		}
		log.Debug("[SOCKS5] udp associate", "client", c.RemoteAddr().String(), "udp", caddr.String())
		ch := make(chan byte)
		srv.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer srv.AssociatedUDP.Delete(caddr.String())
		io.Copy(io.Discard, c) //nolint:errcheck
		log.Debug("[SOCKS5] udp associate tcp closed", "udp", caddr.String())
		return nil
	}

	if r.Cmd != socks5.CmdConnect {
		return s.replyError(c, r, socks5.RepCommandNotSupported)
	}

	target := r.Address()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		log.Error("[SOCKS5] parse target", "target", target, "err", err)
		return s.replyError(c, r, socks5.RepServerFailure)
	}

	if s.router.ShouldIPV6Disable() && util.IsIPV6(host) {
		log.Warn("[SOCKS5] ipv6 target rejected, ipv6 disabled", "target", target)
		return s.replyError(c, r, socks5.RepNotAllowed)
	}

	local := c.RemoteAddr().String()
	rule := s.router.MatchHostRule(host)
	switch rule {
	case router.HostRuleBlock:
		log.Info("[TCP_BLOCK] blocked", "host", host, "target", target, "local", local)
		return s.replyError(c, r, socks5.RepNotAllowed)
	case router.HostRuleDirect:
		log.Info("[TCP_DIRECT]", "target", target, "local", local)
		rc, err := s.directTCPConnect(c, r, target)
		if err != nil {
			log.Error("[TCP_DIRECT] connect", "target", target, "err", err)
			return err
		}
		defer rc.Close() //nolint:errcheck
		relayTCP(rc, c)
		log.Debug("[TCP_DIRECT] relay finished", "target", target)
		return nil
	case router.HostRuleProxy:
		log.Info("[TCP_PROXY]", "target", target, "local", local)
		a, bindAddr, bindPort, err := socks5.ParseAddress(c.LocalAddr().String())
		if err != nil {
			log.Error("[TCP_PROXY] parse local addr", "err", err)
			return s.replyError(c, r, socks5.RepServerFailure)
		}
		if a == socks5.ATYPDomain {
			bindAddr = bindAddr[1:]
		}
		p := socks5.NewReply(socks5.RepSuccess, a, bindAddr, bindPort)
		if _, err := p.WriteTo(c); err != nil {
			log.Error("[TCP_PROXY] reply", "err", err)
			return err
		}
		err = s.handler.OpenTCPStream(context.Background(), target, s.method, c)
		if err != nil {
			if errors.Is(err, ErrStreamIdleTimeout) || errors.Is(err, ErrStreamReset) {
				log.Debug("[TCP_PROXY] closed", "target", target, "err", err)
				return nil
			}
			log.Error("[TCP_PROXY] stream", "target", target, "err", err)
		} else {
			log.Debug("[TCP_PROXY] stream finished", "target", target)
		}
		return err
	}

	return nil
}

func (s *Socks5Server) directTCPConnect(c net.Conn, r *socks5.Request, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	defer cancel()

	rc, err := s.directDialContext(ctx, "tcp", target)
	if err != nil {
		_ = s.replyError(c, r, socks5.RepHostUnreachable)
		return nil, err
	}

	a, bindAddr, bindPort, err := socks5.ParseAddress(rc.LocalAddr().String())
	if err != nil {
		rc.Close() //nolint:errcheck
		_ = s.replyError(c, r, socks5.RepHostUnreachable)
		return nil, err
	}
	if a == socks5.ATYPDomain {
		bindAddr = bindAddr[1:]
	}
	p := socks5.NewReply(socks5.RepSuccess, a, bindAddr, bindPort)
	if _, err := p.WriteTo(c); err != nil {
		rc.Close() //nolint:errcheck
		return nil, err
	}

	return rc, nil
}

func (s *Socks5Server) UDPHandle(srv *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	return s.handleUDP(srv, addr, d)
}

func (s *Socks5Server) replyError(c net.Conn, r *socks5.Request, rep byte) error {
	var p *socks5.Reply
	if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
		p = socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	} else {
		p = socks5.NewReply(rep, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0, 0})
	}
	_, err := p.WriteTo(c)
	return err
}

func relayTCP(dst, src net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(src, dst)
		// Half-close src symmetrically so the peer learns that no more data
		// will be written on this direction. Without this, a client waiting
		// for the remote half-close to signal end-of-response would hang.
		if cw, ok := src.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

func (s *Socks5Server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.udpMu.Lock()
			for key, ue := range s.udpExch {
				if time.Since(ue.LastSeen()) > s.udpIdleTimeout {
					log.Debug("[UDP_PROXY] idle cleanup", "key", key)
					ue.Close() //nolint:errcheck
					delete(s.udpExch, key)
				}
			}
			s.udpMu.Unlock()
		case <-s.quit:
			return
		}
	}
}
