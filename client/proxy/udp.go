package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/txthinking/socks5"

	easydns "github.com/nange/easyss/v3/client/dns"
)

func (s *Socks5Server) handleUDP(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram) error {
	src := clientAddr.String()
	dst := d.Address()

	_, hasAssoc := srv.AssociatedUDP.Get(src)
	_ = hasAssoc

	host, port, _ := net.SplitHostPort(dst)
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

	isDirect := rule == router.HostRuleDirect

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
	var lastErr error
	for _, addr := range easydns.DirectDNSServers {
		if s.router.ShouldIPV6Disable() && util.IsIPV6Addr(addr) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
		resp, err := s.exchangeDirectDNS(ctx, msg, addr)
		cancel()
		if err != nil {
			lastErr = err
			continue
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
	log.Error("[DNS_DIRECT]", "domain", domain, "err", lastErr)
	return lastErr
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
	dst := easydns.ProxyDNSServer
	key := clientAddr.String() + "_" + dst

	ue, created, err := s.getOrCreateUDPExchange(key, dst)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", dst, "err", err)
		return err
	}
	if created {
		go s.receiveLoop(ue, srv, clientAddr, dst, key)
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

// getOrCreateUDPExchange returns the existing UDPExchange for key, or creates
// one via OpenUDPExchange(dst). If this call created the exchange, created is
// true and the caller is responsible for starting receiveLoop. If another
// goroutine is already creating the exchange, this call blocks until that
// completes and returns the shared exchange (created == false). This eliminates
// the previous TOCTOU race where two concurrent packets could each create an
// exchange, with the second overwriting (and leaking) the first.
func (s *Socks5Server) getOrCreateUDPExchange(key, dst string) (ue *UDPExchange, created bool, err error) {
	s.udpMu.Lock()
	if existing, ok := s.udpExch[key]; ok {
		s.udpMu.Unlock()
		return existing, false, nil
	}
	if f, ok := s.udpInflight[key]; ok {
		s.udpMu.Unlock()
		<-f.done
		return f.ue, false, f.err
	}
	f := &udpExchangeFactory{done: make(chan struct{})}
	s.udpInflight[key] = f
	s.udpMu.Unlock()

	ue, err = s.handler.OpenUDPExchange(context.Background(), dst, s.method)
	f.ue, f.err = ue, err
	close(f.done)

	if err != nil {
		s.udpMu.Lock()
		delete(s.udpInflight, key)
		s.udpMu.Unlock()
		return nil, false, err
	}
	s.udpMu.Lock()
	s.udpExch[key] = ue
	delete(s.udpInflight, key)
	s.udpMu.Unlock()
	return ue, true, nil
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
	conn, ok := s.directUDP[key]
	s.udpMu.RUnlock()

	if ok {
		_, err := conn.Write(d.Data)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	rc, err := s.directDialContext(ctx, "udp", dst)
	cancel()
	if err != nil {
		return err
	}

	s.udpMu.Lock()
	s.directUDP[key] = rc
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

	ue, created, err := s.getOrCreateUDPExchange(key, dst)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", dst, "err", err)
		return err
	}
	if created {
		go s.receiveLoop(ue, srv, clientAddr, dst, key)
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
