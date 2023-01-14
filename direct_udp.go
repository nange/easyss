package easyss

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/nange/easyss/util/bytespool"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
	"github.com/xjasonlyu/tun2socks/v2/component/dialer"
)

// DefaultDirectDNSServers the servers are dns servers from tencent, aliyun and baidu
var DefaultDirectDNSServers = [3]string{"119.29.29.29:53", "223.5.5.5:53", "180.76.76.76:53"}

const DirectSuffix = "direct"

// DirectUDPExchange used to store client address and remote connection
type DirectUDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.PacketConn
}

func (ss *Easyss) directUDPRelay(s *socks5.Server, laddr *net.UDPAddr, d *socks5.Datagram, isDNSReq bool) error {
	logPrefix := "[UDP_DIRECT]"
	if isDNSReq {
		logPrefix = "[DNS_DIRECT]"
	}
	log.Infof("%s target:%s", logPrefix, d.Address())

	var ch chan struct{}
	var hasAssoc bool

	portStr := strconv.FormatInt(int64(laddr.Port), 10)
	asCh, ok := s.AssociatedUDP.Get(portStr)
	if ok {
		hasAssoc = true
		ch = asCh.(chan struct{})
		log.Debugf("%s found the associate with tcp, src:%s, dst:%s", logPrefix, laddr.String(), d.Address())
	} else {
		log.Debugf("%s the udp addr:%v doesn't associate with tcp, dst addr:%v", logPrefix, laddr.String(), d.Address())
	}

	dst := d.Address()
	rewrittenDst := dst
	if isDNSReq {
		rewrittenDst = ss.DirectDNSServer()
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
			log.Debugf("%s sent data: %s <--> %s", logPrefix, ue.ClientAddr.String(), addr.String())
		}
		return nil
	}

	var ue *DirectUDPExchange
	var src = laddr.String()
	iue, ok := s.UDPExchanges.Get(src + dst + DirectSuffix)
	if ok {
		ue = iue.(*DirectUDPExchange)
		return send(ue, d.Data, uAddr)
	}

	pc, err := ss.directUDPConn()
	if err != nil {
		log.Errorf("%s listen packet err:%v", logPrefix, err)
		return err
	}

	ue = &DirectUDPExchange{
		ClientAddr: laddr,
		RemoteConn: pc,
	}
	if err := send(ue, d.Data, uAddr); err != nil {
		log.Warnf("%s send data to %s, err:%v", logPrefix, uAddr.String(), err)
		return err
	}
	s.UDPExchanges.Set(src+dst+DirectSuffix, ue, -1)

	go func() {
		var buf = bytespool.Get(MaxUDPDataSize)
		defer func() {
			bytespool.MustPut(buf)
			s.UDPExchanges.Delete(src + dst + DirectSuffix)
			ue.RemoteConn.Close()
		}()

		for {
			select {
			case <-ch:
				log.Infof("%s the tcp that udp address %s associated closed", logPrefix, ue.ClientAddr.String())
				return
			default:
			}
			if !hasAssoc {
				var err error
				if isDNSReq {
					err = ue.RemoteConn.SetDeadline(time.Now().Add(DefaultDNSTimeout))
				} else {
					err = ue.RemoteConn.SetDeadline(time.Now().Add(ss.Timeout()))
				}
				if err != nil {
					log.Errorf("%s set the deadline for remote conn err:%v", logPrefix, err)
					return
				}
			}

			n, _, err := ue.RemoteConn.ReadFrom(buf)
			if err != nil {
				return
			}
			log.Debugf("%s got data from remote. client: %v, data-len: %v", logPrefix, ue.ClientAddr.String(), len(buf[0:n]))

			// if is dns response, set result to dns cache
			ss.SetDNSCacheIfNeeded(buf[0:n], true)

			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				log.Errorf("%s parse dst address err:%v", logPrefix, err)
				return
			}
			d1 := socks5.NewDatagram(a, addr, port, buf[0:n])
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), laddr); err != nil {
				return
			}
		}
	}()

	return nil
}

func (ss *Easyss) directUDPConn() (net.PacketConn, error) {
	var pc net.PacketConn
	var err error
	if ss.EnabledTun2socks() {
		pc, err = dialer.ListenPacketWithOptions("udp", "", &dialer.Options{
			InterfaceName:  ss.LocalDevice(),
			InterfaceIndex: ss.LocalDeviceIndex(),
		})
	} else {
		pc, err = net.ListenPacket("udp", "")
	}

	return pc, err
}
