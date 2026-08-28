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
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/relay"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/txthinking/socks5"
	"golang.org/x/sync/singleflight"

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

	udpMu   sync.RWMutex
	udpExch map[string]*UDPExchange
	// udpExchangeSF deduplicates concurrent OpenUDPExchange calls for the
	// same (client, target) key; udpInflightCount tracks how many creations
	// are in flight so the exchange cap can account for them.
	udpExchangeSF    singleflight.Group
	udpInflightCount atomic.Int64
	directUDP        map[string]*directUDPConn
	// directUDPSF deduplicates concurrent direct-UDP dials for the same
	// (client, target) key.
	directUDPSF    singleflight.Group
	quit           chan struct{}
	closeOnce      sync.Once
	udpIdleTimeout time.Duration
	// dnsRespTimeout bounds how long a proxied-DNS exchange may go without
	// any server response before it is closed (read-idle timeout). Only DNS
	// exchanges enable it; 0 disables the mechanism. It exists because the
	// 60s udpIdleTimeout never fires for exchanges whose client keeps
	// retrying queries (each Send refreshes lastSeen) while the upstream DNS
	// server stays silent.
	dnsRespTimeout time.Duration
	started        atomic.Bool
	closing        atomic.Bool
}

// directUDPConn pairs a direct-UDP socket with its last-write timestamp so
// the cleanup loop can recycle sessions whose remote peer went silent.
type directUDPConn struct {
	conn     net.Conn
	lastSeen atomic.Int64 // UnixNano, refreshed on every datagram written
}

func NewSocks5Server(listenAddr, username, password string, handler *StreamHandler, rt *router.Router, serverDomain string, method protocol.Method, disableQUIC bool, dialTimeout, udpIdleTimeout, dnsRespTimeout time.Duration, directDialContext func(context.Context, string, string) (net.Conn, error)) (*Socks5Server, error) {
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
		dnsCache:          easydns.NewCache(serverDomain),
		serverDomain:      serverDomain,
		method:            method,
		disableQUIC:       disableQUIC,
		directDialContext: directDialContext,
		dialTimeout:       dialTimeout,
		udpExch:           make(map[string]*UDPExchange),
		directUDP:         make(map[string]*directUDPConn),
		quit:              make(chan struct{}),
		udpIdleTimeout:    udpIdleTimeout,
		dnsRespTimeout:    dnsRespTimeout,
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
// given domain, trying each of the given dns servers in order and falling
// back to the system dns servers when all of them fail. This avoids a DNS
// deadlock when TUN routes are active.
func (s *Socks5Server) PrePopulateDNS(domain string, dnsServers []string, requireIPv4 bool) error {
	return s.dnsCache.PrePopulateWithFallback(domain, dnsServers, requireIPv4)
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

// waitForAccept polls the listen address until the server has really
// started accepting connections. A plain TCP dial is not enough: it
// succeeds as soon as the listener is bound at the kernel level, before
// the accept loop inside the txthinking/socks5 runnergroup library has
// registered its runners. Calling Shutdown in that window either leaks
// the listener (runnergroup.Done returns early when no runner has been
// added yet) or deadlocks (Done skips runners whose start goroutine has
// not run yet, then blocks forever waiting for a done signal that never
// comes). Probing with a real SOCKS5 greeting and requiring a reply
// only succeeds once the accept loop is up, so Close can never race
// with the goroutine spawned by Start.
func (s *Socks5Server) waitForAccept() {
	if s.srv == nil {
		return
	}
	addr := s.srv.Addr
	if addr == "" {
		return
	}
	// SOCKS5 greeting: version 5, one offered method, no auth. The
	// server only answers after the accept loop accepted our connection
	// and parsed the greeting.
	greeting := []byte{0x05, 0x01, 0x00}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if probeSocks5Accept(addr, greeting) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// probeSocks5Accept dials addr and performs a SOCKS5 negotiation. It
// reports whether the server accepted the connection and replied to the
// greeting, which proves the accept loop is up and registered.
func probeSocks5Accept(addr string, greeting []byte) bool {
	c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer c.Close() //nolint:errcheck
	if err := c.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return false
	}
	if _, err := c.Write(greeting); err != nil {
		return false
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		return false
	}
	return reply[0] == 0x05
}

func (s *Socks5Server) Close() error {
	s.closing.Store(true)
	s.closeOnce.Do(func() { close(s.quit) })
	if s.started.Load() {
		s.waitForAccept()
	}
	var exchanges []*UDPExchange
	s.udpMu.Lock()
	for key, ue := range s.udpExch {
		delete(s.udpExch, key)
		exchanges = append(exchanges, ue)
	}
	for key, dc := range s.directUDP {
		dc.conn.Close() //nolint:errcheck
		delete(s.directUDP, key)
	}
	s.udpMu.Unlock()
	// Close the exchanges outside the lock: Close flushes a FIN through the
	// HTTP/2 stream (an io.Pipe write), which can block on transport
	// backpressure — holding s.udpMu there would freeze all UDP handling.
	// closeOnce makes this safe against the receiveLoop's own Close.
	for _, ue := range exchanges {
		ue.Close() //nolint:errcheck
	}
	// In-flight exchange creations are reaped by the creator itself: after
	// OpenUDPExchange returns it observes the closing flag, closes the
	// exchange and removes the factory entry (see getOrCreateUDPExchange).
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
			if isTransientStreamError(err) {
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

// directRelayIdleTimeout bounds how long a direct TCP relay may sit idle
// before both connections are torn down. The proxied path enforces its own
// idle timeout via relay.Bidirectional (StreamHandler.streamIdleTimeout);
// the direct path previously had no deadline at all, so a silent or
// half-open peer left the two copy goroutines and their sockets leaked
// forever.
const directRelayIdleTimeout = 300 * time.Second

// relayTCP copies bytes in both directions between dst and src with a shared
// idle timeout, mirroring the proxied path's relay semantics: on clean EOF a
// half-close is propagated, and on idle timeout or error both connections
// are closed exactly once.
func relayTCP(dst, src net.Conn) {
	result := relay.Bidirectional(directRelayIdleTimeout, func() {
		_ = dst.Close()
		_ = src.Close()
	},
		func(signalActivity func()) error { return copyHalfClose(dst, src, signalActivity) },
		func(signalActivity func()) error { return copyHalfClose(src, dst, signalActivity) },
	)
	if result.Err != nil && !result.TimedOut &&
		!errors.Is(result.Err, io.EOF) &&
		!errors.Is(result.Err, io.ErrClosedPipe) &&
		!isLocalConnClosedError(result.Err) {
		log.Debug("[TCP_DIRECT] relay copy error", "err", result.Err)
	}
}

// copyHalfClose streams src to dst, signalling activity on every read and
// half-closing dst on clean EOF.
func copyHalfClose(dst, src net.Conn, signalActivity func()) error {
	buf := bytespool.Get(config.TCPStreamBufferSize)
	defer bytespool.MustPut(buf)
	for {
		n, rErr := src.Read(buf)
		if n > 0 {
			signalActivity()
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				if cw, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				return nil
			}
			return rErr
		}
	}
}

func (s *Socks5Server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var stale []*UDPExchange
			s.udpMu.Lock()
			for key, ue := range s.udpExch {
				if time.Since(ue.LastSeen()) > s.udpIdleTimeout {
					log.Debug("[UDP_PROXY] idle cleanup", "key", key)
					delete(s.udpExch, key)
					stale = append(stale, ue)
				}
			}
			// Direct UDP sessions get the same idle recycling: a remote peer
			// that stops responding (or a datagram flow that simply ended)
			// must not pin the socket and its reader goroutine until the
			// 2-minute read deadline fires.
			for key, dc := range s.directUDP {
				if time.Since(time.Unix(0, dc.lastSeen.Load())) > s.udpIdleTimeout {
					log.Debug("[UDP_DIRECT] idle cleanup", "key", key)
					dc.conn.Close() //nolint:errcheck
					delete(s.directUDP, key)
				}
			}
			s.udpMu.Unlock()
			// Close evicted exchanges outside the lock: Close flushes a FIN
			// through the HTTP/2 stream (an io.Pipe write), which can block
			// on transport backpressure — holding s.udpMu there would freeze
			// all UDP handling. closeOnce makes this safe against the
			// receiveLoop's own Close.
			for _, ue := range stale {
				ue.Close() //nolint:errcheck
			}
		case <-s.quit:
			return
		}
	}
}
