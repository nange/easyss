package easyss

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easypool"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

const (
	MaxUDPDataSize   = 65507
	DefaultDNSServer = "8.8.8.8:53"
)

const DefaultUDPTimeout = 10 * time.Second

var udpDataBytes = util.NewBytes(MaxUDPDataSize)

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.Conn
}

func (ss *Easyss) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	log.Debugf("[SOCKS5_UDP] enter udp handdle, local_addr:%v, remote_addr:%v", addr.String(), d.Address())

	dst := d.Address()
	rewrittenDst := dst

	msg := &dns.Msg{}
	err := msg.Unpack(d.Data)
	if err == nil && isDNSRequest(msg) {
		question := msg.Question[0]
		isDirect := ss.HostShouldDirect(strings.TrimSuffix(question.Name, "."))

		// find from dns cache first
		msgCache := ss.DNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect)
		if msgCache != nil {
			msgCache.MsgHdr.Id = msg.MsgHdr.Id
			log.Infof("[DNS_CACHE] find %s from cache, qtype:%s", question.Name, dns.TypeToString[question.Qtype])
			if err := responseDNSMsg(s.UDPConn, addr, msgCache, d.Address()); err != nil {
				log.Errorf("[DNS_CACHE] write msg back err:%s", err.Error())
				return err
			}
			if strings.TrimSuffix(question.Name, ".") != ss.Server() {
				log.Debugf("[DNS_CACHE] renew cache for domain:%s", question.Name)
				ss.RenewDNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect)
			}
			return nil
		}

		if isDirect {
			log.Infof("[DNS_DIRECT] domain:%s, qtype:%s", question.Name, dns.TypeToString[question.Qtype])
			return ss.directUDPRelay(s, addr, d, true)
		}

		log.Infof("[DNS_PROXY] domain:%s, qtype:%s", msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])

		log.Debugf("[DNS_PROXY] rewrite dns dst to %s", DefaultDNSServer)
		rewrittenDst = DefaultDNSServer
	}

	dstHost, _, _ := net.SplitHostPort(rewrittenDst)
	if ss.HostShouldDirect(dstHost) {
		return ss.directUDPRelay(s, addr, d, isDNSRequest(msg))
	}

	if err := ss.validateAddr(rewrittenDst); err != nil {
		log.Warnf("[UDP_PROXY] validate dst:%v err:%v", dst, err)
		return errors.New("dst addr is invalid")
	}

	var ch chan byte
	var hasAssoc bool

	portStr := strconv.FormatInt(int64(addr.Port), 10)
	asCh, ok := s.AssociatedUDP.Get(portStr)
	if ok {
		hasAssoc = true
		ch = asCh.(chan byte)
		log.Debugf("[UDP_PROXY] found the associate with tcp, src:%s, dst:%s", addr.String(), d.Address())
	} else {
		log.Debugf("[UDP_PROXY] the addr:%v doesn't associate with tcp, dst addr:%v", addr.String(), d.Address())
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
		log.Debugf("[UDP_PROXY] sent data to remote from: %s", ue.ClientAddr.String())
		return nil
	}

	var ue *UDPExchange
	var src = addr.String()
	iue, ok := s.UDPExchanges.Get(src + dst)
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	pool := ss.Pool()
	if pool == nil {
		log.Errorf("[UDP_PROXY] failed to get pool, easyss is closed")
		return errors.New("easyss is closed")
	}

	stream, err := pool.Get()
	if err != nil {
		log.Errorf("[UDP_PROXY] get stream from pool err:%+v", err)
		return err
	}

	if err := ss.handShakeWithRemote(stream, rewrittenDst, "udp"); err != nil {
		log.Errorf("[UDP_PROXY] handshake with remote server err:%v", err)
		if pc, ok := stream.(*easypool.PoolConn); ok {
			log.Debugf("[UDP_PROXY] mark pool conn stream unusable")
			pc.MarkUnusable()
			stream.Close()
		}
		return err
	}

	csStream, err := cipherstream.New(stream, ss.Password(), ss.Method(), "udp")
	if err != nil {
		log.Errorf("[UDP_PROXY] new cipherstream err:%+v, password:%v, method:%v",
			err, ss.Password(), ss.Method())
		return err
	}

	ue = &UDPExchange{
		ClientAddr: addr,
		RemoteConn: csStream,
	}
	if err := send(ue, d.Data); err != nil {
		markCipherStreamUnusable(ue.RemoteConn)
		ue.RemoteConn.Close()
		return err
	}
	s.UDPExchanges.Set(src+dst, ue, -1)

	var monitorCh = make(chan bool, 1)
	// monitor the assoc tcp connection to be closed and try to reuse the underlying connection
	go func() {
		var tryReuse bool
		select {
		case <-ch:
			if err := expireConn(ue.RemoteConn); err != nil {
				log.Errorf("[UDP_PROXY] expire remote conn: %s", err.Error())
			}
			tryReuse = <-monitorCh
		case tryReuse = <-monitorCh:
		}
		if err := ue.RemoteConn.SetDeadline(time.Time{}); err != nil {
			tryReuse = false
		}

		reuse := false
		if tryReuse {
			log.Debugf("[UDP_PROXY] request is finished, try to reuse underlying tcp connection")
			reuse = tryReuseForUDPClient(ue.RemoteConn, ss.Timeout())
		}

		if !reuse {
			markCipherStreamUnusable(ue.RemoteConn)
			log.Infof("[UDP_PROXY] underlying proxy connection is unhealthy, need close it")
		} else {
			log.Infof("[UDP_PROXY] underlying proxy connection is healthy, so reuse it")
		}

		ue.RemoteConn.(*cipherstream.CipherStream).Release()
		stream.Close()
	}()

	go func(ue *UDPExchange, dst string) {
		defer func() {
			s.UDPExchanges.Delete(src + dst)
		}()

		var b = udpDataBytes.Get(MaxUDPDataSize)
		defer udpDataBytes.Put(b)
		for {
			select {
			case <-ch:
				log.Infof("[UDP_PROXY] the tcp that udp address %s associated closed", ue.ClientAddr.String())
				monitorCh <- true
				return
			default:
			}

			if !hasAssoc {
				if err := ue.RemoteConn.SetDeadline(time.Now().Add(DefaultUDPTimeout)); err != nil {
					log.Errorf("[UDP_PROXY] set the deadline for remote conn err:%v", err)
					monitorCh <- false
					return
				}
			}
			n, err := ue.RemoteConn.Read(b[:])
			if err != nil {
				if err == cipherstream.ErrTimeout {
					monitorCh <- true
				} else {
					monitorCh <- false
				}
				return
			}
			log.Debugf("[UDP_PROXY] got data from remote. client: %v, data-len: %v", ue.ClientAddr.String(), len(b[0:n]))

			// if is dns response, set result to dns cache
			ss.SetDNSCacheIfNeeded(b[0:n], false)

			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				monitorCh <- true
				log.Errorf("[UDP_PROXY] parse dst address err:%v", err)
				return
			}
			d1 := socks5.NewDatagram(a, addr, port, b[0:n])
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
				monitorCh <- true
				return
			}
		}
	}(ue, dst)

	return nil
}

func (ss *Easyss) SetDNSCacheIfNeeded(udpResp []byte, isDirect bool) {
	logPrefix := "[DNS_PROXY]"
	if isDirect {
		logPrefix = "[DNS_DIRECT]"
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(udpResp); err == nil && isDNSResponse(msg) {
		log.Infof("%s got result:%s for domain:%s, qtype:%s",
			logPrefix, msg.Answer, msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])

		if err := ss.SetDNSCache(msg, false, isDirect); err != nil {
			log.Warnf("%s set dns cache err:%s", logPrefix, err.Error())
		} else {
			log.Debugf("%s set cache for domain:%s, qtype:%s",
				logPrefix, msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
		}
	}
}

func responseDNSMsg(conn *net.UDPConn, localAddr *net.UDPAddr, msg *dns.Msg, remoteAddr string) error {
	a, _addr, port, _ := socks5.ParseAddress(remoteAddr)
	pack, _ := msg.Pack()
	d1 := socks5.NewDatagram(a, _addr, port, pack)

	_, err := conn.WriteToUDP(d1.Bytes(), localAddr)
	return err
}

func expireConn(conn net.Conn) error {
	return conn.SetDeadline(time.Unix(0, 0))
}

func isDNSRequest(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	if len(msg.Question) > 0 {
		return true
	}
	return false
}

func isDNSResponse(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	if !msg.MsgHdr.Response || !isDNSRequest(msg) || len(msg.Answer) == 0 {
		return false
	}
	return true
}

func tryReuseForUDPClient(cipher net.Conn, timeout time.Duration) bool {
	if err := setCipherDeadline(cipher, timeout); err != nil {
		return false
	}
	if err := CloseWrite(cipher); err != nil {
		return false
	}
	if !readACK(cipher) {
		return false
	}
	if !readFIN(cipher) {
		return false
	}
	if err := writeACK(cipher); err != nil {
		return false
	}
	if err := cipher.SetDeadline(time.Time{}); err != nil {
		return false
	}

	return true
}
