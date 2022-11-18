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

var udpDataBytes = util.NewBytes(MaxUDPDataSize)

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.Conn
}

func (ss *Easyss) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	log.Debugf("enter udp handdle, local_addr:%v, remote_addr:%v", addr.String(), d.Address())

	dst := d.Address()
	rewrittenDst := dst

	msg := &dns.Msg{}
	err := msg.Unpack(d.Data)
	if err == nil && isDNSRequest(msg) {
		log.Infof("the udp request is dns proto, domain:%s, qtype:%s",
			msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])

		question := msg.Question[0]
		hostAtCN := ss.HostAtCN(strings.TrimSuffix(question.Name, "."))
		isDirect := hostAtCN && ss.Tun2socksStatusAuto()

		// find from dns cache first
		msgCache := ss.DNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect)
		if msgCache != nil {
			msgCache.MsgHdr.Id = msg.MsgHdr.Id
			log.Infof("find msg from dns cache, write back directly, domain:%s, qtype:%s",
				question.Name, dns.TypeToString[question.Qtype])
			if err := responseDNSMsg(s.UDPConn, addr, msgCache, d.Address()); err != nil {
				log.Errorf("response dns msg err:%s", err.Error())
				return err
			}
			if strings.TrimSuffix(question.Name, ".") != ss.Server() {
				log.Debugf("renew dns cache for domain:%s", question.Name)
				ss.RenewDNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect)
			}
			return nil
		}

		if isDirect {
			return ss.directUDPRelay(s, addr, d, true)
		}

		log.Debugf("rewrite dns dst addr to %s", DefaultDNSServer)
		rewrittenDst = DefaultDNSServer
	} else if err := ss.validateAddr(dst); err != nil {
		log.Warnf("validate udp dst:%v err:%v, data:%s", dst, err, string(d.Data))
		return errors.New("dst addr is invalid")
	}

	dstHost, _, _ := net.SplitHostPort(dst)
	if ss.HostAtCN(dstHost) && ss.Tun2socksStatusAuto() {
		return ss.directUDPRelay(s, addr, d, false)
	}

	var ch chan byte
	var hasAssoc bool

	portStr := strconv.FormatInt(int64(addr.Port), 10)
	asCh, ok := s.AssociatedUDP.Get(portStr)
	if ok {
		hasAssoc = true
		ch = asCh.(chan byte)
		log.Debugf("found the associate with tcp, src:%s, dst:%s", addr.String(), d.Address())
	} else {
		log.Debugf("the udp addr:%v doesn't associate with tcp, dst addr:%v", addr.String(), d.Address())
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
		log.Debugf("Sent UDP data to remote. client: %s", ue.ClientAddr.String())
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
		log.Errorf("failed to get pool, easyss is closed")
		return errors.New("easyss is closed")
	}

	stream, err := pool.Get()
	if err != nil {
		log.Errorf("get stream from pool failed:%+v", err)
		return err
	}

	if err := ss.handShakeWithRemote(stream, rewrittenDst, "udp"); err != nil {
		log.Errorf("handshake with remote server err:%v", err)
		if pc, ok := stream.(*easypool.PoolConn); ok {
			log.Debugf("mark pool conn stream unusable")
			pc.MarkUnusable()
			stream.Close()
		}
		return err
	}

	csStream, err := cipherstream.New(stream, ss.Password(), ss.Method(), "udp")
	if err != nil {
		log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
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
			expireConn(ue.RemoteConn)
			tryReuse = <-monitorCh
		case tryReuse = <-monitorCh:
		}

		if tryReuse {
			log.Debugf("udp request is finished, try reusing underlying tcp connection")
			buf := connStateBytes.Get(32)
			defer connStateBytes.Put(buf)

			state := NewConnState(FIN_WAIT1, buf)
			setCipherDeadline(ue.RemoteConn, ss.Timeout())
			for stateFn := state.fn; stateFn != nil; {
				stateFn = stateFn(ue.RemoteConn).fn
			}
			if state.err != nil {
				log.Infof("state err:%v, state:%v", state.err, state.state)
				markCipherStreamUnusable(ue.RemoteConn)
			} else {
				log.Debugf("underlying connection is health, so reuse it")
			}
		} else {
			markCipherStreamUnusable(ue.RemoteConn)
		}
		ue.RemoteConn.Close()
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
				log.Infof("the tcp that udp address %s associated closed", ue.ClientAddr.String())
				monitorCh <- true
				return
			default:
			}

			if !hasAssoc {
				if err := ue.RemoteConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					log.Errorf("set the deadline for remote conn err:%v", err)
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
			log.Debugf("got UDP data from remote. client: %v, data-len: %v", ue.ClientAddr.String(), len(b[0:n]))

			// if is dns response, set result to dns cache
			ss.SetDNSCacheIfNeeded(b[0:n], false)

			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				monitorCh <- true
				log.Errorf("parse dst address err:%v", err)
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
	msg := &dns.Msg{}
	if err := msg.Unpack(udpResp); err == nil && isDNSResponse(msg) {
		if err := ss.SetDNSCache(msg, false, isDirect); err != nil {
			log.Warnf("set dns cache err:%s", err.Error())
		} else {
			log.Debugf("set dns cache success for domain:%s, qtype:%s, isDirect:%v",
				msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype], isDirect)
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

func isDNSRequest(msg *dns.Msg) bool {
	if len(msg.Question) > 0 {
		return true
	}
	return false
}

func isDNSResponse(msg *dns.Msg) bool {
	if !msg.MsgHdr.Response || !isDNSRequest(msg) || len(msg.Answer) == 0 {
		return false
	}
	return true
}
