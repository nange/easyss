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
	return s.proxyDNSQuery(srv, clientAddr, msg, domain)
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

// dnsPendingEntry records one in-flight DNS query forwarded over the shared
// proxied-DNS stream: the original transaction ID and client to restore and
// route the response back to, the dedup group hash it belongs to, and the
// deadline after which an unanswered query is dropped (see sweepDNS).
type dnsPendingEntry struct {
	origID   uint16
	client   *net.UDPAddr
	hash     uint64
	deadline time.Time
}

// defaultDNSRespTimeout bounds how long an unanswered proxied-DNS query may
// stay pending before it is dropped, applied when dnsRespTimeout is not
// configured (<= 0).
const defaultDNSRespTimeout = 10 * time.Second

// proxyDNSQuery forwards one DNS query to the upstream proxy DNS server over
// a single shared HTTP/2 stream. Every proxied DNS query — from any client
// and any source port — shares the one stream keyed by the upstream address,
// so a burst of concurrent queries (which previously opened one stream per
// (client address, target)) can no longer inflate the transport's bulk
// connection pool. Because the stream is shared, each query's transaction ID
// is rewritten to a globally unique ID (allocDNSID) and the response is
// routed back by the shared receive loop (receiveLoopSharedDNS). Concurrent
// byte-identical queries (differing only in the transaction ID) are merged
// into a single upstream round trip via dnsDedup.
func (s *Socks5Server) proxyDNSQuery(srv *socks5.Server, clientAddr *net.UDPAddr, msg *dns.Msg, domain string) error {
	dst := config.ProxyDNSServer
	key := "dns_" + dst

	// Rewrite the transaction ID before forwarding: the shared stream
	// carries queries from every client, so the original per-client IDs may
	// collide. The rewritten ID is what the shared receive loop uses to
	// route the response back.
	origID := msg.Id
	rid := s.allocDNSID()
	msg.Id = rid
	packed, err := msg.Pack()
	if err != nil {
		log.Error("[UDP_PROXY] pack dns query", "domain", domain, "err", err)
		return err
	}

	// Register the pending response before any receive loop can process it
	// (on a fresh stream the query rides inside the bootstrap record).
	respTimeout := s.dnsRespTimeout
	if respTimeout <= 0 {
		respTimeout = defaultDNSRespTimeout
	}
	hash := dnsQueryHash(packed)
	s.dnsPendingMu.Lock()
	s.dnsPending[rid] = dnsPendingEntry{
		origID:   origID,
		client:   clientAddr,
		hash:     hash,
		deadline: time.Now().Add(respTimeout),
	}
	s.dnsPendingMu.Unlock()

	// Merge concurrent identical queries (same bytes except the ID) into
	// one upstream round trip: receiveLoopSharedDNS clones the primary
	// response to the waiters.
	s.dnsDedupMu.Lock()
	if group, ok := s.dnsDedup[hash]; ok {
		s.dnsDedup[hash] = append(group, rid)
		s.dnsDedupMu.Unlock()
		log.Debug("[DNS_PROXY] deduplicated concurrent query", "domain", domain, "qtype", dns.TypeToString[msg.Question[0].Qtype])
		return nil
	}
	s.dnsDedup[hash] = []uint16{rid}
	s.dnsDedupMu.Unlock()

	ue, created, err := s.getOrCreateUDPExchange(key, dst, packed)
	if err != nil {
		s.dropDNSPending(rid, hash)
		log.Error("[UDP_PROXY] open exchange", "dst", dst, "err", err)
		return err
	}
	if created {
		go s.receiveLoopSharedDNS(ue, srv, dst, key)
		return nil // first payload already sent in handshake
	}

	if err := ue.Send(packed); err != nil {
		s.dropDNSPending(rid, hash)
		log.Error("[UDP_PROXY] send", "err", err)
		s.udpMu.Lock()
		delete(s.udpExch, key)
		s.udpMu.Unlock()
		ue.Close() //nolint:errcheck
		return err
	}
	return nil
}

// allocDNSID returns a globally unique 16-bit DNS transaction ID for a query
// on the shared proxied-DNS stream. Pending entries live at most
// dnsRespTimeout, so the counter effectively never wraps into a live ID; on
// the theoretical collision the counter is bumped until a free ID is found.
func (s *Socks5Server) allocDNSID() uint16 {
	for {
		rid := uint16(s.dnsNextID.Add(1))
		if rid == 0 {
			continue
		}
		s.dnsPendingMu.Lock()
		_, busy := s.dnsPending[rid]
		s.dnsPendingMu.Unlock()
		if !busy {
			return rid
		}
	}
}

// dnsQueryHash hashes a packed DNS query with the transaction ID bytes
// skipped, so byte-identical queries that differ only in their ID hash alike
// and can share one upstream round trip. The rest of the packet — flags,
// question, EDNS options — participates, so queries with different attributes
// are never merged.
func dnsQueryHash(packed []byte) uint64 {
	const (
		offset64 = 14695981039346656037 // FNV-1a 64-bit offset basis
		prime64  = 1099511628211
	)
	var h uint64 = offset64
	for i, c := range packed {
		if i < 2 { // DNS transaction ID
			continue
		}
		h ^= uint64(c)
		h *= prime64
	}
	return h
}

// dropDNSPending removes a pending query whose upstream round trip failed
// before any response could arrive, and updates its dedup group: when the
// primary failed the whole group is dead (no upstream query exists to answer
// the waiters), otherwise the waiter is just unregistered.
func (s *Socks5Server) dropDNSPending(rid uint16, hash uint64) {
	s.dnsPendingMu.Lock()
	delete(s.dnsPending, rid)
	s.dnsPendingMu.Unlock()

	s.dnsDedupMu.Lock()
	defer s.dnsDedupMu.Unlock()
	group, ok := s.dnsDedup[hash]
	if !ok {
		return
	}
	if len(group) > 0 && group[0] == rid {
		delete(s.dnsDedup, hash)
		return
	}
	for i, w := range group {
		if w == rid {
			group = append(group[:i], group[i+1:]...)
			break
		}
	}
	if len(group) == 0 {
		delete(s.dnsDedup, hash)
	} else {
		s.dnsDedup[hash] = group
	}
}

// sweepDNS drops pending proxied-DNS responses whose deadline elapsed (the
// upstream DNS server stayed silent) and cleans up their dedup groups. Unlike
// the old per-client exchange close, this never tears down the shared stream:
// only stale pending entries are discarded, so one stuck query cannot affect
// the other clients' in-flight queries. Run from the cleanup loop.
func (s *Socks5Server) sweepDNS() {
	now := time.Now()
	var expired []uint16
	s.dnsPendingMu.Lock()
	for rid, e := range s.dnsPending {
		if now.After(e.deadline) {
			expired = append(expired, rid)
			delete(s.dnsPending, rid)
		}
	}
	s.dnsPendingMu.Unlock()
	if len(expired) == 0 {
		return
	}

	s.dnsDedupMu.Lock()
	defer s.dnsDedupMu.Unlock()
	for hash, group := range s.dnsDedup {
		if containsRID(expired, group[0]) {
			// The primary expired: no upstream query is in flight for the
			// group, so the waiters could never be answered — drop the
			// whole group (their pending entries expire on their own).
			delete(s.dnsDedup, hash)
			continue
		}
		kept := group[:0]
		for _, rid := range group {
			if !containsRID(expired, rid) {
				kept = append(kept, rid)
			}
		}
		if len(kept) != len(group) {
			s.dnsDedup[hash] = kept
		}
	}
}

func containsRID(list []uint16, rid uint16) bool {
	for _, r := range list {
		if r == rid {
			return true
		}
	}
	return false
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
	var evicted *UDPExchange
	if len(s.udpExch)+len(s.udpInflight) >= maxUDPExchanges {
		evicted = s.evictOldestExchangeLocked()
	}
	f := &udpExchangeFactory{done: make(chan struct{})}
	s.udpInflight[key] = f
	s.udpMu.Unlock()

	// Close the evicted exchange outside the lock: Close flushes a FIN
	// through the HTTP/2 stream (an io.Pipe write), which can block on
	// transport backpressure — holding s.udpMu there would freeze all UDP
	// handling. closeOnce makes this safe against the receiveLoop's own
	// deferred Close.
	if evicted != nil {
		evicted.Close() //nolint:errcheck
	}

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

// evictOldestExchangeLocked selects the exchange that has been idle the
// longest and removes it from the map, bounding the live exchange count at
// maxUDPExchanges. The evicted exchange is returned without being closed:
// the caller must close it after releasing s.udpMu, since UDPExchange.Close
// flushes a FIN through the HTTP/2 stream (an io.Pipe write) and can block
// on transport backpressure — holding s.udpMu there would freeze all UDP
// handling. closeOnce makes the deferred close safe against the
// receiveLoop's own Close.
func (s *Socks5Server) evictOldestExchangeLocked() *UDPExchange {
	var oldestKey string
	var oldestTime time.Time
	for k, ue := range s.udpExch {
		last := ue.LastSeen()
		if oldestKey == "" || last.Before(oldestTime) {
			oldestKey, oldestTime = k, last
		}
	}
	if oldestKey == "" {
		return nil
	}
	log.Debug("[UDP_PROXY] exchange cap reached, evicting oldest idle", "key", oldestKey)
	evicted := s.udpExch[oldestKey]
	delete(s.udpExch, oldestKey)
	return evicted
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
		if err := msg.Unpack(data); err == nil && util.IsDNSResponse(msg) && len(msg.Question) > 0 {
			s.handleDNSResponse(srv, msg, clientAddr, target)
			continue
		}
		s.sendToClient(srv, clientAddr, data, target)
	}
}

// handleDNSResponse applies the client-side DNS response handling (AAAA
// stripping when IPv6 is disabled, cache population, custom-proxy-domain IP
// learning, logging) and delivers the response to the given client. The
// message ID must already be restored to the originating client's ID.
func (s *Socks5Server) handleDNSResponse(srv *socks5.Server, msg *dns.Msg, clientAddr *net.UDPAddr, dst string) {
	if len(msg.Question) > 0 && s.router.ShouldIPV6Disable() && msg.Question[0].Qtype == dns.TypeAAAA {
		msg.Answer = nil
	}
	packed, err := msg.Pack()
	if err != nil {
		log.Debug("[UDP_PROXY] pack dns response", "err", err)
		return
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
	s.sendToClient(srv, clientAddr, packed, dst)
}

// receiveLoopSharedDNS reads responses on the shared proxied-DNS stream and
// routes each back to the originating client via the rewritten transaction ID
// (see proxyDNSQuery). Concurrent identical queries (dnsDedup) are answered
// by cloning the primary response. Unlike the per-client receiveLoop, an
// unanswered query never closes the shared stream — its pending entry simply
// expires and is swept (see sweepDNS), so one stuck query cannot kill the
// other clients' in-flight queries.
func (s *Socks5Server) receiveLoopSharedDNS(ue *UDPExchange, srv *socks5.Server, dst, key string) {
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
		if err := msg.Unpack(data); err != nil || !util.IsDNSResponse(msg) || len(msg.Question) == 0 {
			continue
		}

		rid := msg.Id
		s.dnsPendingMu.Lock()
		entry, ok := s.dnsPending[rid]
		if ok {
			delete(s.dnsPending, rid)
		}
		s.dnsPendingMu.Unlock()
		if !ok {
			// Stale or unknown ID (late response, or the query was swept):
			// drop it rather than misrouting to a client.
			continue
		}

		// Restore the primary client's ID and deliver.
		msg.Id = entry.origID
		s.handleDNSResponse(srv, msg, entry.client, dst)

		// Fan out to byte-identical waiters from the dedup group.
		s.dnsDedupMu.Lock()
		group := s.dnsDedup[entry.hash]
		delete(s.dnsDedup, entry.hash)
		s.dnsDedupMu.Unlock()
		for _, w := range group {
			if w == rid {
				continue // the primary itself
			}
			s.dnsPendingMu.Lock()
			wEntry, ok := s.dnsPending[w]
			if ok {
				delete(s.dnsPending, w)
			}
			s.dnsPendingMu.Unlock()
			if !ok {
				continue
			}
			clone := *msg
			clone.Id = wEntry.origID
			s.handleDNSResponse(srv, &clone, wEntry.client, dst)
		}
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
			// Refresh the idle timestamp on receive as well as send, mirroring
			// the proxied path (UDPExchange.Receive): a flow that keeps
			// receiving but never writes again (a one-shot query with a long
			// stream of responses) must not be reaped while it is still
			// active.
			dc.lastSeen.Store(time.Now().UnixNano())
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
		// Non-DNS UDP must not use the short read-idle timeout: a session
		// may legitimately stay silent for a long time (e.g. an upload-only
		// flow), so it keeps the 60s bidirectional idle reaper only.
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
