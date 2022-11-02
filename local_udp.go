package easyss

import (
	"fmt"
	"net"
	"time"

	"github.com/nange/easypool"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.Conn
}

func (ss *Easyss) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	log.Debugf("enter udp handdle, local_addr:%v, remote_addr:%v", addr.String(), d.Address())

	var ch chan byte
	var hasAssoc bool
	src := addr.String()
	asCh, ok := s.AssociatedUDP.Get(src)
	if ok {
		hasAssoc = true
		ch = asCh.(chan byte)
		log.Infof("found the associate with tcp, src:%s, dst:%s", src, d.Address())
	} else {
		log.Infof("the udp addr:%v doesn't associate with tcp, dst addr:%v", src, d.Address())
	}

	send := func(ue *UDPExchange, data []byte) error {
		select {
		case <-ch:
			return fmt.Errorf("the tcp that udp address %s associated closed", src)
		default:
		}
		_, err := ue.RemoteConn.Write(data)
		if err != nil {
			return err
		}
		log.Debugf("Sent UDP data to remote. client: %#v", ue.ClientAddr.String())
		return nil
	}

	dst := d.Address()
	host, _, err := net.SplitHostPort(dst)
	if util.IsPrivateIP(host) {
		// On Matsuri APP, the rDNS(in-addr.arpa) request may use private ip as dst
		// One possible solution is rewritten the dst to 8.8.8.8:53
		log.Debugf("rewrite dst addr to 8.8.8.8:53")
		dst = "8.8.8.8:53"
	} else if err := ss.validateAddr(dst); err != nil {
		log.Warnf("validate udp dst:%v err:%v, data:%s", dst, err, string(d.Data))
		return errors.New("dst addr is invalid")
	}

	var ue *UDPExchange
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

	if err = ss.handShakeWithRemote(stream, dst, "udp"); err != nil {
		log.Errorf("hand-shake with remote server err:%v", err)
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
			log.Infof("udp request is finished, try reusing underlying tcp connection")
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
				log.Infof("underlying connection is health, so reuse it")
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

		var b [65507]byte
		for {
			select {
			case <-ch:
				log.Infof("The tcp that udp address %s associated closed\n", ue.ClientAddr.String())
				monitorCh <- true
				return
			default:
			}
			if !hasAssoc && s.UDPTimeout > 0 {
				if err := ue.RemoteConn.SetDeadline(time.Now().Add(time.Duration(s.UDPTimeout) * time.Second)); err != nil {
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
			log.Debugf("Got UDP data from remote. client: %v  data-len: %v\n", ue.ClientAddr.String(), len(b[0:n]))

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
			log.Debugf("Write Datagram to client. client: %#v  data: %#v %#v %#v %#v %#v %#v\n",
				ue.ClientAddr.String(), d1.Rsv, d1.Frag, d1.Atyp, d1.DstAddr, d1.DstPort, len(d1.Data))
		}
	}(ue, dst)

	return nil
}
