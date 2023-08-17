package easyss

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/txthinking/socks5"
	"github.com/xjasonlyu/tun2socks/v2/dialer"
)

// DefaultDirectDNSServers the servers are dns servers from tencent, aliyun and baidu
var DefaultDirectDNSServers = [3]string{"119.29.29.29:53", "223.5.5.5:53", "180.76.76.76:53"}
var DefaultDNSServerDomains = [3]string{"dnspod.cn", "alidns.com", "dudns.baidu.com"}

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

	var ch chan struct{}
	var hasAssoc bool

	portStr := strconv.FormatInt(int64(laddr.Port), 10)
	asCh, ok := s.AssociatedUDP.Get(portStr)
	if ok {
		hasAssoc = true
		ch = asCh.(chan struct{})
		log.Debug(logPrefix+" found the associate with tcp", "src", laddr.String(), "dst", d.Address())
	} else {
		log.Debug(logPrefix+" the udp addr doesn't associate with tcp", logPrefix, "udp_addr", laddr.String(), "dst_addr", d.Address())
	}

	dst := d.Address()
	rewrittenDst := dst
	if isDNSReq {
		rewrittenDst = ss.DirectDNSServer()
	}
	log.Info(logPrefix, "target", rewrittenDst)

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
			log.Debug(logPrefix+" sent data", "from", ue.ClientAddr.String(), "to", addr.String())
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
		log.Error(logPrefix+" listen packet", "err", err)
		return err
	}

	ue = &DirectUDPExchange{
		ClientAddr: laddr,
		RemoteConn: pc,
	}
	if err := send(ue, d.Data, uAddr); err != nil {
		log.Warn(logPrefix+" send data", "to", uAddr.String(), "err", err)
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
				log.Info(logPrefix+" the tcp that udp address associated closed", "udp_address", ue.ClientAddr.String())
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
					log.Error(logPrefix+" set the deadline for remote conn", "err", err)
					return
				}
			}

			n, _, err := ue.RemoteConn.ReadFrom(buf)
			if err != nil {
				return
			}
			log.Debug(logPrefix+" got data from remote", "client", ue.ClientAddr.String(), "data_len", len(buf[0:n]))

			// if is dns response, set result to dns cache
			_msg := ss.SetDNSCacheIfNeeded(buf[0:n], true)

			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				log.Error(logPrefix+" parse dst address", "err", err)
				return
			}
			data := buf[0:n]
			if _msg != nil {
				data, _ = _msg.Pack()
			}
			d1 := socks5.NewDatagram(a, addr, port, data)
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
	network := "udp"
	if ss.DisableIPV6() {
		network = "udp4"
	}
	if ss.EnabledTun2socks() {
		pc, err = dialer.ListenPacketWithOptions(network, "", &dialer.Options{
			InterfaceName:  ss.LocalDevice(),
			InterfaceIndex: ss.LocalDeviceIndex(),
		})
	} else {
		pc, err = net.ListenPacket(network, "")
	}

	return pc, err
}
