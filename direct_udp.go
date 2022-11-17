package easyss

import (
	"fmt"
	"net"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
	"github.com/xjasonlyu/tun2socks/v2/component/dialer"
)

const DefaultDirectDNSServer = "114.114.114.114:53"

// DirectUDPExchange used to store client address and remote connection
type DirectUDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.PacketConn
}

func (ss *Easyss) directUDPRelay(s *socks5.Server, laddr *net.UDPAddr, d *socks5.Datagram, isDNSReq bool) error {
	log.Infof("directly relay udp proto for addr:%s, isDNSReq:%v", d.Address(), isDNSReq)

	var ch chan byte
	var hasAssoc bool

	portStr := strconv.FormatInt(int64(laddr.Port), 10)
	asCh, ok := s.AssociatedUDP.Get(portStr)
	if ok {
		hasAssoc = true
		ch = asCh.(chan byte)
		log.Debugf("found the associate with tcp, src:%s, dst:%s", laddr.String(), d.Address())
	} else {
		log.Debugf("the udp addr:%v doesn't associate with tcp, dst addr:%v", laddr.String(), d.Address())
	}

	dst := d.Address()
	rewrittenDst := dst
	if isDNSReq {
		rewrittenDst = DefaultDirectDNSServer
	}
	uAddr, _ := net.ResolveUDPAddr("udp", rewrittenDst)

	send := func(ue *DirectUDPExchange, data []byte, addr net.Addr) error {
		select {
		case <-ch:
			return fmt.Errorf("this udp address %s is not associated with tcp", ue.ClientAddr.String())
		default:
			_, err := ue.RemoteConn.WriteTo(data, addr)
			if err != nil {
				return err
			}
			log.Debugf("directly sent UDP data to remote:%s, client: %s", addr.String(), ue.ClientAddr.String())
		}
		return nil
	}

	var ue *DirectUDPExchange
	var src = laddr.String()
	iue, ok := s.UDPExchanges.Get(src + dst)
	if ok {
		ue = iue.(*DirectUDPExchange)
		return send(ue, d.Data, uAddr)
	}

	pc, err := dialer.ListenPacketWithOptions("udp", "", &dialer.Options{
		InterfaceName:  ss.LocalDevice(),
		InterfaceIndex: ss.LocalDeviceIndex(),
	})
	if err != nil {
		log.Errorf("listen packet err:%v", err)
		return err
	}

	ue = &DirectUDPExchange{
		ClientAddr: laddr,
		RemoteConn: pc,
	}
	if err := send(ue, d.Data, uAddr); err != nil {
		log.Warnf("directly write udp request data to %s, err:%v", uAddr.String(), err)
		return err
	}
	s.UDPExchanges.Set(src+dst, ue, -1)

	go func() {
		var b = udpDataBytes.Get(MaxUDPDataSize)
		defer func() {
			udpDataBytes.Put(b)
			s.UDPExchanges.Delete(src + dst)
			ue.RemoteConn.Close()
		}()

		for {
			select {
			case <-ch:
				log.Infof("the tcp that udp address %s associated closed", ue.ClientAddr.String())
				return
			default:
			}
			if !hasAssoc {
				if err := ue.RemoteConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					log.Errorf("set the deadline for remote conn err:%v", err)
					return
				}
			}

			n, _, err := ue.RemoteConn.ReadFrom(b)
			if err != nil {
				return
			}
			log.Debugf("directly got UDP data from remote. client: %v, data-len: %v", ue.ClientAddr.String(), len(b[0:n]))

			// if is dns response, set result to dns cache
			ss.SetDNSCacheIfNeeded(b[0:n], true)

			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				log.Errorf("parse dst address err:%v", err)
				return
			}
			d1 := socks5.NewDatagram(a, addr, port, b[0:n])
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), laddr); err != nil {
				return
			}
		}
	}()

	return nil
}
