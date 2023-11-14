package easyss

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
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
)

const DefaultDNSTimeout = 5 * time.Second

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.Conn
}

func (ss *Easyss) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	log.Debug("[SOCKS5_UDP] enter udp handle", "local_addr", addr.String(), "remote_addr", d.Address())

	dst := d.Address()
	rewrittenDst := dst

	msg := &dns.Msg{}
	err := msg.Unpack(d.Data)
	isDNSReq := isDNSRequest(msg)
	if err == nil && isDNSReq {
		question := msg.Question[0]
		isDirect := ss.HostShouldDirect(strings.TrimSuffix(question.Name, "."))

		// find from dns cache first
		msgCache := ss.DNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect)
		if msgCache != nil {
			msgCache.MsgHdr.Id = msg.MsgHdr.Id
			log.Info("[DNS_CACHE] find from cache", "domain", question.Name, "qtype", dns.TypeToString[question.Qtype])
			if err := responseDNSMsg(s.UDPConn, addr, msgCache, d.Address()); err != nil {
				log.Error("[DNS_CACHE] write msg back", "err", err)
				return err
			}
			if strings.TrimSuffix(question.Name, ".") != ss.Server() {
				log.Debug("[DNS_CACHE] renew cache for", "domain", question.Name)
				ss.RenewDNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect)
			}
			return nil
		}

		if isDirect {
			log.Info("[DNS_DIRECT]", "domain", question.Name, "qtype", dns.TypeToString[question.Qtype])
			return ss.directUDPRelay(s, addr, d, true)
		}

		log.Info("[DNS_PROXY]", "domain", msg.Question[0].Name, "qtype", dns.TypeToString[msg.Question[0].Qtype])

		log.Debug("[DNS_PROXY] rewrite dns dst to", "server", DefaultDNSServer)
		rewrittenDst = DefaultDNSServer
	}

	dstHost, _, _ := net.SplitHostPort(rewrittenDst)
	if ss.HostShouldDirect(dstHost) {
		return ss.directUDPRelay(s, addr, d, isDNSReq)
	}

	if !ss.disableValidateAddr {
		if err := ss.validateAddr(rewrittenDst); err != nil {
			log.Warn("[UDP_PROXY] validate", "dst", dst, "err", err)
			return errors.New("dst addr is invalid")
		}
	}

	var ch chan struct{}
	var hasAssoc bool

	portStr := strconv.FormatInt(int64(addr.Port), 10)
	asCh, ok := s.AssociatedUDP.Get(portStr)
	if ok {
		hasAssoc = true
		ch = asCh.(chan struct{})
		log.Debug("[UDP_PROXY] found the associate with tcp", "src", addr.String(), "dst", d.Address())
	} else {
		ch = make(chan struct{}, 2)
		log.Debug("[UDP_PROXY] the addr doesn't associate with tcp", "addr", addr.String(), "dst", d.Address())
	}

	send := func(ue *UDPExchange, data []byte) error {
		select {
		case <-ch:
			return fmt.Errorf("the tcp that udp address %s associated closed", ue.ClientAddr.String())
		default:
		}
		_, err := ue.RemoteConn.Write(data)
		if err != nil {
			return err
		}
		log.Debug("[UDP_PROXY] sent data to remote", "from", ue.ClientAddr.String())
		return nil
	}

	var ue *UDPExchange
	var exchKey = addr.String() + dst
	ss.lockKey(exchKey)
	defer ss.unlockKey(exchKey)

	iue, ok := s.UDPExchanges.Get(exchKey)
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	flag := cipherstream.FlagUDP
	if isDNSReq {
		flag |= cipherstream.FlagDNS
	}
	csStream, err := ss.handShakeWithRemote(rewrittenDst, flag)
	if err != nil {
		log.Error("[UDP_PROXY] handshake with remote server", "err", err)
		if csStream != nil {
			MarkCipherStreamUnusable(csStream)
			csStream.Close()
		}
		return err
	}

	ue = &UDPExchange{
		ClientAddr: addr,
		RemoteConn: csStream,
	}
	if err := send(ue, d.Data); err != nil {
		MarkCipherStreamUnusable(ue.RemoteConn)
		ue.RemoteConn.Close()
		return err
	}
	s.UDPExchanges.Set(exchKey, ue, -1)

	var monitorCh = make(chan bool)
	// monitor the assoc tcp connection to be closed and try to reuse the underlying connection
	go func() {
		var tryReuse bool
		select {
		case <-ch:
			if err := expireConn(ue.RemoteConn); err != nil {
				log.Error("[UDP_PROXY] expire remote conn", "err", err)
			}
			tryReuse = <-monitorCh
		case tryReuse = <-monitorCh:
		}
		if err := ue.RemoteConn.SetReadDeadline(time.Time{}); err != nil {
			tryReuse = false
		}

		if tryReuse {
			log.Debug("[UDP_PROXY] request is finished, try to reuse underlying tcp connection")
			reuse := tryReuseInUDPClient(ue.RemoteConn, ss.Timeout())
			if reuse != nil {
				MarkCipherStreamUnusable(ue.RemoteConn)
				log.Warn("[UDP_PROXY] underlying proxy connection is unhealthy, need close it", "reuse", reuse)
			} else {
				log.Debug("[UDP_PROXY] underlying proxy connection is healthy, so reuse it")
			}
		} else {
			MarkCipherStreamUnusable(ue.RemoteConn)
		}

		ue.RemoteConn.Close()
	}()

	go func(ue *UDPExchange, dst string) {
		var tryReuse = true
		if !ss.IsNativeOutboundProto() {
			tryReuse = false
		}

		defer func() {
			ss.lockKey(exchKey)
			defer ss.unlockKey(exchKey)

			monitorCh <- tryReuse
			ch <- struct{}{}
			s.UDPExchanges.Delete(exchKey)
		}()

		var buf = bytespool.Get(MaxUDPDataSize)
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
					err = ue.RemoteConn.SetReadDeadline(time.Now().Add(DefaultDNSTimeout))
				} else {
					err = ue.RemoteConn.SetReadDeadline(time.Now().Add(ss.Timeout()))
				}
				if err != nil {
					log.Error("[UDP_PROXY] set the deadline for remote conn err", "err", err)
					tryReuse = false
					return
				}
			}
			n, err := ue.RemoteConn.Read(buf[:])
			if err != nil {
				if !errors.Is(err, cipherstream.ErrTimeout) {
					tryReuse = false
					log.Info("[UDP_PROXY] remote conn read", "err", err)
				}
				return
			}
			log.Debug("[UDP_PROXY] got data from remote", "client", ue.ClientAddr.String(), "data_len", len(buf[0:n]))

			// if is dns response, set result to dns cache
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
	}(ue, dst)

	return nil
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
		if ss.DisableIPV6() && msg.Question[0].Qtype == dns.TypeAAAA {
			log.Info(logPrefix+" ipv6 is disabled, set TypeAAAA dns answer to nil for", "domain", msg.Question[0].Name)
			msg.Answer = nil
		}
		if err := ss.SetDNSCache(msg, false, isDirect); err != nil {
			log.Warn(logPrefix+" set dns cache", logPrefix, "err", err)
		} else {
			log.Debug(logPrefix+" set cache for", "domain", msg.Question[0].Name, "qtype", dns.TypeToString[msg.Question[0].Qtype])
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
	if !msg.MsgHdr.Response || !isDNSRequest(msg) {
		return false
	}
	return true
}

func tryReuseInUDPClient(cipher net.Conn, timeout time.Duration) error {
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
