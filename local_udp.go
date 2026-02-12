package easyss

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/txthinking/socks5"
)

const (
	MaxUDPDataSize   = 65507
	DefaultDNSServer = "8.8.8.8:53"
	MaxUDPConnCount  = 16
)

const DefaultDNSTimeout = 5 * time.Second

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	Conns      []net.Conn
	mu         sync.Mutex
	cond       *sync.Cond
	Pending    int
	ActiveReqs int32
}

func (ss *Easyss) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	log.Debug("[SOCKS5_UDP] enter udp handle", "local_addr", addr.String(), "remote_addr", d.Address())

	dst := d.Address()
	rewrittenDst := dst

	msg := &dns.Msg{}
	if err := msg.Unpack(d.Data); err == nil && isDNSRequest(msg) {
		handled, err := ss.handleDNS(s, addr, d, msg)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
		log.Debug("[DNS_PROXY] rewrite dns dst to", "server", DefaultDNSServer)
		rewrittenDst = DefaultDNSServer
	}

	dstHost, port, _ := net.SplitHostPort(rewrittenDst)
	if ss.MatchHostRule(dstHost) == HostRuleDirect {
		return ss.directUDPRelay(s, addr, d, isDNSRequest(msg))
	}

	if err := ss.validateUDPProxyReq(dstHost, port, rewrittenDst); err != nil {
		return err
	}

	ch, hasAssoc := ss.getAssociatedChan(s, addr, d)
	ue, exchKey := ss.getOrCreateUDPExchange(s, addr, dst)
	atomic.AddInt32(&ue.ActiveReqs, 1)
	defer atomic.AddInt32(&ue.ActiveReqs, -1)

	isQUIC := port == "443"
	conn := ss.getConnFromPool(ue, rewrittenDst, dst, ch, hasAssoc, isDNSRequest(msg), isQUIC, exchKey, s)
	if conn == nil {
		return errors.New("get conn from pool failed")
	}
	if isQUIC {
		log.Info("[UDP_PROXY]", "exch_key", exchKey, "active_reqs", atomic.LoadInt32(&ue.ActiveReqs), "conn_count", len(ue.Conns))
	}

	return ss.sendUDPData(conn, d.Data, ch, addr)
}

func (ss *Easyss) handleDNS(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram, msg *dns.Msg) (bool, error) {
	question := msg.Question[0]
	rule := ss.MatchHostRule(strings.TrimSuffix(question.Name, "."))

	if rule == HostRuleBlock {
		return true, responseBlockedDNSMsg(s.UDPConn, addr, msg, d.Address())
	}
	if ss.ShouldIPV6Disable() && question.Qtype == dns.TypeAAAA {
		return true, responseEmptyDNSMsg(s.UDPConn, addr, msg, d.Address())
	}

	isDirect := rule == HostRuleDirect
	if msgCache := ss.DNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect); msgCache != nil {
		msgCache.Id = msg.Id
		log.Info("[DNS_CACHE] find from cache", "domain", question.Name, "qtype", dns.TypeToString[question.Qtype])
		if err := responseDNSMsg(s.UDPConn, addr, msgCache, d.Address()); err != nil {
			log.Error("[DNS_CACHE] write msg back", "err", err)
			return true, err
		}
		if strings.TrimSuffix(question.Name, ".") != ss.Server() {
			log.Debug("[DNS_CACHE] renew cache for", "domain", question.Name)
			ss.RenewDNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect)
		}
		return true, nil
	}

	if isDirect {
		log.Info("[DNS_DIRECT]", "domain", question.Name, "qtype", dns.TypeToString[question.Qtype])
		return true, ss.directUDPRelay(s, addr, d, true)
	}

	log.Info("[DNS_PROXY]", "domain", msg.Question[0].Name, "qtype", dns.TypeToString[msg.Question[0].Qtype])
	return false, nil
}

func (ss *Easyss) validateUDPProxyReq(dstHost, port, rewrittenDst string) error {
	if port == "443" && ss.DisableQUIC() {
		log.Info("[UDP_PROXY] quic is disabled", "dst", rewrittenDst)
		return errors.New("quic is disabled")
	}
	if !ss.disableValidateAddr {
		if err := ss.validateAddr(rewrittenDst); err != nil {
			log.Warn("[UDP_PROXY] validate", "dst", rewrittenDst, "err", err)
			return errors.New("dst addr is invalid")
		}
	}
	return nil
}

func (ss *Easyss) getAssociatedChan(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) (chan struct{}, bool) {
	portStr := strconv.FormatInt(int64(addr.Port), 10)
	asCh, ok := s.AssociatedUDP.Get(portStr)
	if ok {
		log.Debug("[UDP_PROXY] found the associate with tcp", "src", addr.String(), "dst", d.Address())
		return asCh.(chan struct{}), true
	}
	log.Debug("[UDP_PROXY] the addr doesn't associate with tcp", "addr", addr.String(), "dst", d.Address())
	return make(chan struct{}, 2), false
}

func (ss *Easyss) getOrCreateUDPExchange(s *socks5.Server, addr *net.UDPAddr, dst string) (*UDPExchange, string) {
	exchKey := addr.String() + dst
	if iue, ok := s.UDPExchanges.Get(exchKey); ok {
		return iue.(*UDPExchange), exchKey
	}

	ss.lockKey(exchKey)
	defer ss.unlockKey(exchKey)

	if iue, ok := s.UDPExchanges.Get(exchKey); ok {
		return iue.(*UDPExchange), exchKey
	}

	ue := &UDPExchange{
		ClientAddr: addr,
	}
	ue.cond = sync.NewCond(&ue.mu)
	s.UDPExchanges.Set(exchKey, ue, -1)
	return ue, exchKey
}

func (ss *Easyss) getConnFromPool(ue *UDPExchange, rewrittenDst, dst string, ch chan struct{}, hasAssoc, isDNSReq, isQUIC bool, exchKey string, s *socks5.Server) net.Conn {
	ue.mu.Lock()
	defer ue.mu.Unlock()

	if len(ue.Conns) == 0 {
		for len(ue.Conns) == 0 {
			if ue.Pending < MaxUDPConnCount {
				ue.Pending++
				go ss.handshakeAndAddConn(ue, rewrittenDst, dst, ch, hasAssoc, isDNSReq, exchKey, s)
			}
			ue.cond.Wait()
		}
	}

	connCount := len(ue.Conns)
	conn := ue.Conns[rand.Intn(connCount)]
	if isQUIC && connCount+ue.Pending < MaxUDPConnCount && atomic.LoadInt32(&ue.ActiveReqs) >= int32(connCount) {
		ue.Pending++
		go ss.handshakeAndAddConn(ue, rewrittenDst, dst, ch, hasAssoc, isDNSReq, exchKey, s)
	}
	return conn
}

func (ss *Easyss) handshakeAndAddConn(ue *UDPExchange, rewrittenDst, dst string, ch chan struct{}, hasAssoc, isDNSReq bool, exchKey string, s *socks5.Server) {
	defer func() {
		ue.mu.Lock()
		ue.Pending--
		ue.cond.Broadcast()
		ue.mu.Unlock()
	}()

	flag := cipherstream.FlagUDP
	if isDNSReq {
		flag |= cipherstream.FlagDNS
	}
	csStream, err := ss.handShakeWithRemote(rewrittenDst, flag)
	if err != nil {
		log.Error("[UDP_PROXY] handshake with remote server", "err", err)
		if csStream != nil {
			if cs, ok := csStream.(*cipherstream.CipherStream); ok {
				cs.MarkConnUnusable()
			}
			_ = csStream.Close()
		}
		return
	}
	ss.addRemoteConn(ue, csStream, dst, ch, hasAssoc, isDNSReq, exchKey, s)
}

func (ss *Easyss) sendUDPData(conn net.Conn, data []byte, ch chan struct{}, addr *net.UDPAddr) error {
	select {
	case <-ch:
		return fmt.Errorf("the tcp that udp address %s associated closed", addr.String())
	default:
	}
	_, err := conn.Write(data)
	if err != nil {
		return err
	}
	log.Debug("[UDP_PROXY] sent data to remote", "from", addr.String())
	return nil
}

func (ss *Easyss) addRemoteConn(ue *UDPExchange, conn net.Conn, dst string, ch chan struct{}, hasAssoc bool, isDNSReq bool, exchKey string, s *socks5.Server) {
	ue.mu.Lock()
	ue.Conns = append(ue.Conns, conn)
	ue.cond.Broadcast()
	ue.mu.Unlock()

	monitorCh := make(chan bool)
	go ss.monitorConnReuse(conn, ch, monitorCh)
	go ss.copyRemoteToLocal(ue, conn, dst, ch, hasAssoc, isDNSReq, exchKey, s, monitorCh)
}

func (ss *Easyss) monitorConnReuse(conn net.Conn, ch chan struct{}, monitorCh chan bool) {
	var tryReuse bool
	select {
	case <-ch:
		if err := expireConn(conn); err != nil {
			log.Error("[UDP_PROXY] expire remote conn", "err", err)
		}
		tryReuse = <-monitorCh
	case tryReuse = <-monitorCh:
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		tryReuse = false
	}

	if tryReuse {
		log.Debug("[UDP_PROXY] request is finished, try to reuse underlying tcp connection")
		reuse := tryReuseInClient(conn, ss.Timeout())
		if reuse != nil {
			if cs, ok := conn.(*cipherstream.CipherStream); ok {
				cs.MarkConnUnusable()
			}
			log.Warn("[UDP_PROXY] underlying proxy connection is unhealthy, need close it", "reuse", reuse)
		} else {
			log.Debug("[UDP_PROXY] underlying proxy connection is healthy, so reuse it")
		}
	} else {
		if cs, ok := conn.(*cipherstream.CipherStream); ok {
			cs.MarkConnUnusable()
		}
	}

	_ = conn.Close()
}

func (ss *Easyss) copyRemoteToLocal(ue *UDPExchange, conn net.Conn, dst string, ch chan struct{}, hasAssoc, isDNSReq bool, exchKey string, s *socks5.Server, monitorCh chan bool) {
	var tryReuse = true
	if !ss.IsNativeOutboundProto() {
		tryReuse = false
	}

	defer func() {
		ue.mu.Lock()
		defer ue.mu.Unlock()

		// remove the conn from the list
		for i, c := range ue.Conns {
			if c == conn {
				ue.Conns = append(ue.Conns[:i], ue.Conns[i+1:]...)
				break
			}
		}
		ue.cond.Broadcast()

		monitorCh <- tryReuse

		if len(ue.Conns) == 0 {
			ss.lockKey(exchKey)
			s.UDPExchanges.Delete(exchKey)
			ss.unlockKey(exchKey)

			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()

	buf := bytespool.Get(MaxUDPDataSize)
	defer bytespool.MustPut(buf)
	for {
		select {
		case <-ch:
			log.Info("[UDP_PROXY] the tcp that udp address associated closed", "udp_addr", ue.ClientAddr.String())
			return
		default:
		}

		if !hasAssoc {
			var err error
			if isDNSReq {
				err = conn.SetReadDeadline(time.Now().Add(DefaultDNSTimeout))
			} else {
				err = conn.SetReadDeadline(time.Now().Add(ss.Timeout()))
			}
			if err != nil {
				log.Error("[UDP_PROXY] set the deadline for remote conn err", "err", err)
				tryReuse = false
				return
			}
		}
		n, err := conn.Read(buf[:])
		if err != nil {
			if !errors.Is(err, cipherstream.ErrTimeout) {
				tryReuse = false
				log.Debug("[UDP_PROXY] remote conn read", "err", err)
			}
			return
		}
		log.Debug("[UDP_PROXY] got data from remote", "client", ue.ClientAddr.String(), "data_len", len(buf[0:n]))

		_msg := ss.SetDNSCacheIfNeeded(buf[0:n], false)

		a, addr, port, err := socks5.ParseAddress(dst)
		if err != nil {
			log.Error("[UDP_PROXY] parse dst address", "err", err)
			return
		}
		data := buf[0:n]
		if _msg != nil {
			data, _ = _msg.Pack()
		}
		d1 := socks5.NewDatagram(a, addr, port, data)
		if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
			return
		}
	}
}

func (ss *Easyss) lockKey(key string) {
	hashVal := xxhash.Sum64String(key)
	lockID := hashVal & UDPLocksAndOpVal
	ss.udpLocks[lockID].Lock()
}

func (ss *Easyss) unlockKey(key string) {
	hashVal := xxhash.Sum64String(key)
	lockID := hashVal & UDPLocksAndOpVal
	ss.udpLocks[lockID].Unlock()
}

func (ss *Easyss) SetDNSCacheIfNeeded(udpResp []byte, isDirect bool) *dns.Msg {
	logPrefix := "[DNS_PROXY]"
	if isDirect {
		logPrefix = "[DNS_DIRECT]"
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(udpResp); err == nil && isDNSResponse(msg) {
		log.Info(logPrefix+" got result for",
			"domain", msg.Question[0].Name, "answer", msg.Answer, "qtype", dns.TypeToString[msg.Question[0].Qtype])
		if err := ss.SetDNSCache(msg, false, isDirect); err != nil {
			log.Warn(logPrefix+" set dns cache", logPrefix, "err", err)
		} else {
			log.Debug(logPrefix+" set cache for", "domain", msg.Question[0].Name, "qtype", dns.TypeToString[msg.Question[0].Qtype])
		}

		if isDirect && len(msg.Question) > 0 {
			domain := msg.Question[0].Name
			domain = strings.TrimSuffix(domain, ".")

			isCustomDirect := false
			ss.customDirectMu.RLock()
			if _, ok := ss.customDirectDomains[domain]; ok {
				isCustomDirect = true
			} else {
				subs := subDomains(domain)
				for _, sub := range subs {
					if _, ok := ss.customDirectDomains[sub]; ok {
						isCustomDirect = true
						break
					}
				}
			}
			ss.customDirectMu.RUnlock()

			if isCustomDirect {
				for _, ans := range msg.Answer {
					if a, ok := ans.(*dns.A); ok {
						ss.SetCustomDirectIP(a.A.String())
						log.Info(logPrefix+" update custom direct ip", "domain", domain, "ip", a.A.String())
					}
				}
			}
		}

		return msg
	}
	return nil
}

func responseDNSMsg(conn *net.UDPConn, localAddr *net.UDPAddr, msg *dns.Msg, remoteAddr string) error {
	a, _addr, port, _ := socks5.ParseAddress(remoteAddr)
	pack, _ := msg.Pack()
	d1 := socks5.NewDatagram(a, _addr, port, pack)

	_, err := conn.WriteToUDP(d1.Bytes(), localAddr)
	return err
}

func responseEmptyDNSMsg(conn *net.UDPConn, localAddr *net.UDPAddr, request *dns.Msg, remoteAddr string) error {
	question := request.Question[0]
	log.Info("[DNS_IPV6_DISABLED]", "domain", question.Name, "qtype", dns.TypeToString[question.Qtype])

	m := new(dns.Msg)
	m.SetReply(request)
	// Do not add any answer, which means empty result

	if err := responseDNSMsg(conn, localAddr, m, remoteAddr); err != nil {
		log.Error("[DNS_IPV6_DISABLED] response", "err", err)
		return err
	}

	return nil
}

func responseBlockedDNSMsg(conn *net.UDPConn, localAddr *net.UDPAddr, request *dns.Msg, remoteAddr string) error {
	question := request.Question[0]
	log.Info("[DNS_BLOCK]", "domain", question.Name, "qtype", dns.TypeToString[question.Qtype])

	m := new(dns.Msg)
	m.SetReply(request)
	switch question.Qtype {
	case dns.TypeA:
		rr, err := dns.NewRR(fmt.Sprintf("%s A 127.0.0.1", question.Name))
		if err != nil {
			log.Error("[DNS_BLOCK] creating A record:", "err", err)
			return err
		}
		m.Answer = append(m.Answer, rr)
	case dns.TypeAAAA:
		rr, err := dns.NewRR(fmt.Sprintf("%s AAAA ::1", question.Name))
		if err != nil {
			log.Error("[DNS_BLOCK] creating AAAA record:", "err", err)
			return err
		}
		m.Answer = append(m.Answer, rr)
	}
	if err := responseDNSMsg(conn, localAddr, m, remoteAddr); err != nil {
		log.Error("[DNS_BLOCK] response", "err", err)
		return err
	}

	return nil
}

func expireConn(conn net.Conn) error {
	return conn.SetReadDeadline(time.Unix(0, 0))
}

func isDNSRequest(msg *dns.Msg) bool {
	if msg == nil || len(msg.Question) == 0 {
		return false
	}
	q := msg.Question[0]
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		return true
	}
	return false
}

func isDNSResponse(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	if !msg.Response || !isDNSRequest(msg) {
		return false
	}
	return true
}

func tryReuseInClient(cipher net.Conn, timeout time.Duration) error {
	if err := cipher.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := CloseWrite(cipher); err != nil {
		return err
	}
	if err := ReadACKFromCipher(cipher); err != nil {
		return err
	}
	if err := readFINFromCipher(cipher); err != nil {
		return err
	}
	if err := WriteACKToCipher(cipher); err != nil {
		return err
	}
	if err := cipher.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	return nil
}

func readFINFromCipher(conn net.Conn) error {
	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	var err error
	for {
		_, err = conn.Read(buf)
		if err != nil {
			break
		}
	}
	if errors.Is(err, cipherstream.ErrFINRSTStream) {
		return nil
	}
	return err
}
