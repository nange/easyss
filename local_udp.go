package easyss

import (
	"fmt"
	"net"
	"time"

	"github.com/nange/easypool"
	"github.com/nange/easyss/cipherstream"
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
	log.Infof("enter udp handdle, local_addr:%v, remote_addr:%v===============", addr.String(), d.Address())

	src := addr.String()
	var ch chan byte
	if s.LimitUDP {
		any, ok := s.AssociatedUDP.Get(src)
		if !ok {
			return fmt.Errorf("This udp address %s is not associated with tcp", src)
		}
		ch = any.(chan byte)
	}
	send := func(ue *UDPExchange, data []byte) error {
		select {
		case <-ch:
			return fmt.Errorf("this udp address %s is not associated with tcp", src)
		default:
			_, err := ue.RemoteConn.Write(data)
			if err != nil {
				return err
			}
			log.Debugf("Sent UDP data to remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), data)
		}
		return nil
	}
	dst := d.Address()
	var ue *UDPExchange
	iue, ok := s.UDPExchanges.Get(src + dst)
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	pool := ss.Pool()
	if pool == nil {
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
		ue.RemoteConn.Close()
		return err
	}
	s.UDPExchanges.Set(src+dst, ue, -1)

	go func(ue *UDPExchange, dst string) {
		defer func() {
			markCipherStreamUnusable(ue.RemoteConn)
			ue.RemoteConn.Close()
			s.UDPExchanges.Delete(ue.ClientAddr.String() + dst)
		}()

		var b [65507]byte
		for {
			select {
			case <-ch:
				log.Infof("The tcp that udp address %s associated closed\n", ue.ClientAddr.String())
				return
			default:
			}
			if s.UDPTimeout != 0 {
				if err := ue.RemoteConn.SetDeadline(time.Now().Add(time.Duration(s.UDPTimeout) * time.Second)); err != nil {
					log.Println(err)
					return
				}
			}
			n, err := ue.RemoteConn.Read(b[:])
			if err != nil {
				return
			}
			log.Infof("Got UDP data from remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), b[0:n])

			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				log.Println(err)
				return
			}
			d1 := socks5.NewDatagram(a, addr, port, b[0:n])
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
				return
			}
			log.Infof("Sent Datagram. client: %#v server: %#v remote: %#v data: %#v %#v %#v %#v %#v %#v datagram address: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), d1.Rsv, d1.Frag, d1.Atyp, d1.DstAddr, d1.DstPort, d1.Data, d1.Address())
		}
	}(ue, dst)

	return nil
}
