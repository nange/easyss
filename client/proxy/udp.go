package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/txthinking/socks5"
)

func (s *Socks5Server) handleUDP(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram) error {
	src := clientAddr.String()
	dst := d.Address()

	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		// Malformed datagram target: drop it instead of opening an exchange
		// with an empty target that the server would reject anyway.
		log.Debug("[UDP] malformed datagram target", "src", src, "target", dst, "err", err)
		return nil
	}
	if s.disableQUIC && port == "443" {
		return nil
	}

	if s.router.ShouldIPV6Disable() && util.IsIPV6(host) {
		log.Warn("[UDP] ipv6 target rejected, ipv6 disabled", "target", dst)
		return nil
	}

	msg := &dns.Msg{}
	if err := msg.Unpack(d.Data); err == nil && util.IsDNSRequest(msg) {
		return s.handleDNS(srv, clientAddr, d, msg)
	}

	return s.handleRegularUDP(srv, clientAddr, d, dst)
}

func (s *Socks5Server) handleDNS(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, msg *dns.Msg) error {
	question := msg.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")
	qtype := dns.TypeToString[question.Qtype]

	rule := s.router.MatchHostRule(domain)
	if rule == router.HostRuleBlock {
		log.Info("[DNS_BLOCK] blocked", "domain", domain, "qtype", qtype)
		return responseBlockedDNSMsg(srv.UDPConn, clientAddr, msg, d.Address())
	}

	// Never take the proxied path for the proxy server's own domain:
	// opening the tunnel to answer the query would require resolving the
	// server domain again, a circular dependency. Fall back to the direct
	// path (bound to the physical interface, bypassing the TUN).
	isServerDomain := s.isServerDomain(domain)
	if isServerDomain {
		log.Info("[DNS_SERVER_DOMAIN] direct", "domain", domain, "qtype", qtype)
	}
	isDirect := isServerDomain || rule == router.HostRuleDirect

	if cached := s.dnsCache.Get(question.Name, qtype, isDirect); cached != nil {
		log.Info("[DNS_CACHE] hit", "domain", domain, "qtype", qtype, "direct", isDirect)
		if s.router.ShouldIPV6Disable() && cached.Question[0].Qtype == dns.TypeAAAA {
			cached.Answer = nil
		}
		cached.Id = msg.Id
		return responseDNSMsg(srv.UDPConn, clientAddr, cached, d.Address())
	}

	if isDirect {
		log.Info("[DNS_DIRECT]", "domain", domain, "qtype", qtype)
		stats.RecordDNSDirectQuery()
		return s.directDNSQuery(srv, clientAddr, d, msg, domain)
	}

	log.Info("[DNS_PROXY]", "domain", domain, "qtype", qtype)
	stats.RecordDNSProxyQuery()
	return s.proxyDNSQuery(srv, clientAddr, d, msg, domain)
}

func (s *Socks5Server) directDNSQuery(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, msg *dns.Msg, domain string) error {
	resp, err := s.exchangeDirectDNSWithFallback(msg, config.DirectDNSServers)
	if err != nil {
		log.Error("[DNS_DIRECT]", "domain", domain, "err", err)
		return err
	}
	if s.router.ShouldIPV6Disable() && msg.Question[0].Qtype == dns.TypeAAAA {
		resp.Answer = nil
	}
	_ = s.dnsCache.Set(resp, true)

	qtype := dns.TypeToString[msg.Question[0].Qtype]
	log.Info("[DNS_DIRECT] result", "domain", domain, "qtype", qtype, "answers", util.DNSAnswerStrings(resp))

	if s.router.IsCustomDirectDomain(domain) {
		for _, ans := range resp.Answer {
			switch a := ans.(type) {
			case *dns.A:
				s.router.AddDirectIP(a.A.String())
			case *dns.AAAA:
				s.router.AddDirectIP(a.AAAA.String())
			case *dns.CNAME:
				s.router.AddDirectDomain(strings.TrimSuffix(a.Target, "."))
			}
		}
	}

	resp.Id = msg.Id
	return responseDNSMsg(srv.UDPConn, clientAddr, resp, d.Address())
}

// exchangeDirectDNSWithFallback exchanges msg with each of the given dns
// servers in order, falling back to the system dns servers when all of them
// fail. The builtin servers are skipped entirely during the circuit breaker
// cool-down after a failure.
func (s *Socks5Server) exchangeDirectDNSWithFallback(msg *dns.Msg, servers []string) (*dns.Msg, error) {
	try := func(servers []string) (*dns.Msg, error) {
		return s.exchangeDirectDNSFromList(msg, servers)
	}
	return easydns.QueryWithBuiltinFirst(servers, easydns.SystemDNSServers(), try)
}

func (s *Socks5Server) exchangeDirectDNSFromList(msg *dns.Msg, servers []string) (*dns.Msg, error) {
	var candidates []string
	for _, addr := range servers {
		if s.router.ShouldIPV6Disable() && util.IsIPV6Addr(addr) {
			continue
		}
		candidates = append(candidates, addr)
	}
	if len(candidates) == 0 {
		return nil, errors.New("no dns server available")
	}

	// Query every upstream concurrently and take the first success. A
	// serial scan lets one hung upstream stall the query for the full
	// per-server timeout — and every datagram's handler goroutine blocks for
	// the whole wait — so a DNS outage would otherwise pile up goroutines.
	// The whole query shares a single timeout budget.
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	defer cancel()

	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, len(candidates))
	for _, addr := range candidates {
		go func(addr string) {
			resp, err := s.exchangeDirectDNS(ctx, msg, addr)
			ch <- result{resp: resp, err: err}
		}(addr)
	}

	var lastErr error
	for range candidates {
		select {
		case r := <-ch:
			if r.err == nil {
				return r.resp, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no dns server available")
	}
	return nil, lastErr
}

func (s *Socks5Server) exchangeDirectDNS(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, error) {
	conn, err := s.directDialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	_ = conn.SetDeadline(time.Now().Add(s.dialTimeout))
	dnsConn := &dns.Conn{Conn: conn, UDPSize: 8192}
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, err
	}
	return dnsConn.ReadMsg()
}

func (s *Socks5Server) proxyDNSQuery(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, msg *dns.Msg, domain string) error {
	dst := config.ProxyDNSServer
	key := clientAddr.String() + "_" + dst

	ue, created, err := s.getOrCreateUDPExchange(key, dst, d.Data)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", dst, "err", err)
		return err
	}
	if created {
		go s.receiveLoop(ue, srv, clientAddr, dst, key)
		return nil // first payload already sent in handshake
	}

	if err := ue.Send(d.Data); err != nil {
		log.Error("[UDP_PROXY] send", "err", err)
		s.udpMu.Lock()
		delete(s.udpExch, key)
		s.udpMu.Unlock()
		ue.Close() //nolint:errcheck
		return err
	}
	return nil
}

// udpExchangeFactory deduplicates concurrent attempts to create a UDPExchange
// for the same key. The first goroutine to need a key performs the (slow)
// OpenUDPExchange call; concurrent waiters block on done and reuse the result.
type udpExchangeFactory struct {
	done chan struct{}
	ue   *UDPExchange
	err  error
}

// maxUDPExchanges bounds the number of concurrent proxied UDP exchanges.
// Each exchange owns one HTTP/2 stream, one receiveLoop goroutine and one
// shaper; keying by (client address, target) means a client that uses a
// fresh ephemeral UDP source port per datagram (Go's net.Resolver, some
// curl builds) would otherwise accumulate hundreds of them within the idle
// window. When the cap is reached, the exchange idle the longest is evicted.
const maxUDPExchanges = 128

// getOrCreateUDPExchange returns the existing UDPExchange for key, or creates
// one via OpenUDPExchange. firstPayload, if non-empty, is merged into the
// bootstrap record when the exchange is newly created (saving one RTT). If
// the exchange already existed, firstPayload is ignored. If this call created
// the exchange, created is true and the caller MUST NOT call ue.Send for the
// first payload (it was already sent in the handshake).
func (s *Socks5Server) getOrCreateUDPExchange(key, dst string, firstPayload []byte) (ue *UDPExchange, created bool, err error) {
	s.udpMu.Lock()
	if existing, ok := s.udpExch[key]; ok {
		s.udpMu.Unlock()
		return existing, false, nil
	}
	if f, ok := s.udpInflight[key]; ok {
		s.udpMu.Unlock()
		<-f.done
		if s.closing.Load() {
			return nil, false, errSocksServerClosed
		}
		return f.ue, false, f.err
	}
	if len(s.udpExch)+len(s.udpInflight) >= maxUDPExchanges {
		s.evictOldestExchangeLocked()
	}
	f := &udpExchangeFactory{done: make(chan struct{})}
	s.udpInflight[key] = f
	s.udpMu.Unlock()

	ue, err = s.handler.OpenUDPExchange(context.Background(), dst, s.method, firstPayload)
	f.ue, f.err = ue, err
	close(f.done)

	if err != nil {
		s.udpMu.Lock()
		delete(s.udpInflight, key)
		s.udpMu.Unlock()
		return nil, false, err
	}
	// The server was closed while the exchange was being created: close it
	// immediately so the stream and its receiveLoop cannot leak past
	// shutdown (the cleanup loop has already exited).
	if s.closing.Load() {
		ue.Close() //nolint:errcheck
		s.udpMu.Lock()
		delete(s.udpInflight, key)
		s.udpMu.Unlock()
		return nil, false, errSocksServerClosed
	}
	s.udpMu.Lock()
	s.udpExch[key] = ue
	delete(s.udpInflight, key)
	s.udpMu.Unlock()
	return ue, true, nil
}

var errSocksServerClosed = errors.New("socks5 udp server closed")

// evictOldestExchangeLocked closes and removes the exchange that has been
// idle the longest, bounding the live exchange count at maxUDPExchanges.
// Caller must hold s.udpMu.
func (s *Socks5Server) evictOldestExchangeLocked() {
	var oldestKey string
	var oldestTime time.Time
	for k, ue := range s.udpExch {
		last := ue.LastSeen()
		if oldestKey == "" || last.Before(oldestTime) {
			oldestKey, oldestTime = k, last
		}
	}
	if oldestKey == "" {
		return
	}
	log.Debug("[UDP_PROXY] exchange cap reached, evicting oldest idle", "key", oldestKey)
	s.udpExch[oldestKey].Close() //nolint:errcheck
	delete(s.udpExch, oldestKey)
}

func (s *Socks5Server) receiveLoop(ue *UDPExchange, srv *socks5.Server, clientAddr *net.UDPAddr, target, key string) {
	defer func() {
		s.udpMu.Lock()
		delete(s.udpExch, key)
		s.udpMu.Unlock()
		ue.Close() //nolint:errcheck
	}()

	for {
		data, err := ue.Receive()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Debug("[UDP_PROXY] receive", "err", err)
			}
			return
		}

		msg := &dns.Msg{}
		if err := msg.Unpack(data); err == nil && util.IsDNSResponse(msg) {
			if s.router.ShouldIPV6Disable() && msg.Question[0].Qtype == dns.TypeAAAA {
				msg.Answer = nil
				if packed, packErr := msg.Pack(); packErr == nil {
					data = packed
				}
			}
			_ = s.dnsCache.Set(msg, false)

			domain := strings.TrimSuffix(msg.Question[0].Name, ".")
			qtype := dns.TypeToString[msg.Question[0].Qtype]
			log.Info("[DNS_PROXY] result", "domain", domain, "qtype", qtype, "answers", util.DNSAnswerStrings(msg))

			if s.router.IsCustomProxyDomain(domain) {
				for _, ans := range msg.Answer {
					switch a := ans.(type) {
					case *dns.A:
						s.router.AddProxyIP(a.A.String())
					case *dns.AAAA:
						s.router.AddProxyIP(a.AAAA.String())
					case *dns.CNAME:
						s.router.AddProxyDomain(strings.TrimSuffix(a.Target, "."))
					}
				}
			}
		}
		s.sendToClient(srv, clientAddr, data, target)
	}
}

func (s *Socks5Server) sendToClient(srv *socks5.Server, clientAddr *net.UDPAddr, data []byte, target string) {
	a, addr, port, err := socks5.ParseAddress(target)
	if err != nil {
		return
	}
	if a == socks5.ATYPDomain {
		addr = addr[1:]
	}
	resp := socks5.NewDatagram(a, addr, port, data)
	if _, err := srv.UDPConn.WriteToUDP(resp.Bytes(), clientAddr); err != nil {
		log.Debug("[UDP] write to client", "err", err)
	}
}

func (s *Socks5Server) handleRegularUDP(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, dst string) error {
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		return err
	}

	rule := s.router.MatchHostRule(host)
	switch rule {
	case router.HostRuleBlock:
		log.Info("[UDP_BLOCK] blocked", "host", host, "target", dst)
		return nil
	case router.HostRuleDirect:
		log.Info("[UDP_DIRECT]", "target", dst)
		return s.directUDPRelay(srv, clientAddr, d, dst)
	case router.HostRuleProxy:
		log.Info("[UDP_PROXY]", "target", dst)
		return s.proxyUDPRelay(srv, clientAddr, d, dst)
	}
	return nil
}

func (s *Socks5Server) directUDPRelay(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, dst string) error {
	key := "direct_" + clientAddr.String() + "_" + dst

	s.udpMu.RLock()
	dc, ok := s.directUDP[key]
	s.udpMu.RUnlock()

	if ok {
		dc.lastSeen.Store(time.Now().UnixNano())
		_, err := dc.conn.Write(d.Data)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	rc, err := s.directDialContext(ctx, "udp", dst)
	cancel()
	if err != nil {
		return err
	}
	dc = &directUDPConn{conn: rc}
	dc.lastSeen.Store(time.Now().UnixNano())

	s.udpMu.Lock()
	s.directUDP[key] = dc
	s.udpMu.Unlock()

	go func() {
		defer func() {
			rc.Close() //nolint:errcheck
			s.udpMu.Lock()
			delete(s.directUDP, key)
			s.udpMu.Unlock()
		}()
		buf := bytespool.Get(protocol.MaxUDPDataSize)
		defer bytespool.MustPut(buf)
		for {
			_ = rc.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := rc.Read(buf)
			if err != nil {
				return
			}
			s.sendToClient(srv, clientAddr, buf[:n], dst)
		}
	}()

	_, err = rc.Write(d.Data)
	return err
}

func (s *Socks5Server) proxyUDPRelay(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, dst string) error {
	key := clientAddr.String() + "_" + dst

	ue, created, err := s.getOrCreateUDPExchange(key, dst, d.Data)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", dst, "err", err)
		return err
	}
	if created {
		go s.receiveLoop(ue, srv, clientAddr, dst, key)
		return nil // first payload already sent in handshake
	}

	if err := ue.Send(d.Data); err != nil {
		log.Error("[UDP_PROXY] send", "err", err)
		s.udpMu.Lock()
		delete(s.udpExch, key)
		s.udpMu.Unlock()
		ue.Close() //nolint:errcheck
		return err
	}
	return nil
}

func responseDNSMsg(conn *net.UDPConn, addr *net.UDPAddr, msg *dns.Msg, dst string) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	a, addrBytes, port, err := ParseAddress(dst)
	if err != nil {
		return err
	}
	if a == socks5.ATYPDomain {
		addrBytes = addrBytes[1:]
	}
	resp := socks5.NewDatagram(a, addrBytes, port, data)
	_, err = conn.WriteToUDP(resp.Bytes(), addr)
	return err
}

func responseBlockedDNSMsg(conn *net.UDPConn, addr *net.UDPAddr, msg *dns.Msg, dst string) error {
	msg.Response = true
	msg.Answer = nil
	msg.Ns = nil
	msg.Extra = nil
	return responseDNSMsg(conn, addr, msg, dst)
}

func ParseAddress(address string) (a byte, addr []byte, port []byte, err error) {
	return socks5.ParseAddress(address)
}
