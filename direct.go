package easyss

import (
	"context"
	"io"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
	"github.com/xjasonlyu/tun2socks/v2/component/dialer"
)

const DefaultDirectDNSServer = "114.114.114.114:53"

func (ss *Easyss) directRelay(localConn net.Conn, addr string) error {
	log.Infof("directly relay for addr:%s", addr)

	ctx, cancel := context.WithTimeout(context.Background(), ss.Timeout())
	defer cancel()

	tConn, err := dialer.DialContextWithOptions(ctx, "tcp", addr, &dialer.Options{
		InterfaceName:  ss.LocalDevice(),
		InterfaceIndex: ss.LocalDeviceIndex(),
	})
	if err != nil {
		log.Errorf("directly dial addr:%s err:%v", addr, err)
		return err
	}
	defer tConn.Close()

	ch1 := make(chan error, 1)
	go func() {
		_, err := io.Copy(tConn, localConn)
		ch1 <- err
	}()

	ch2 := make(chan error, 1)
	go func() {
		_, err := io.Copy(localConn, tConn)
		ch2 <- err
	}()

	for i := 0; i < 2; i++ {
		select {
		case err := <-ch1:
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Warnf("reading from local conn write to remote err:%v", err)
			}
			tConn.Close()
		case err := <-ch2:
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Warnf("reading from remote conn write to local err:%v", err)
			}
			localConn.Close()
		}
	}

	return nil
}

func (ss *Easyss) directUDPRelay(s *socks5.Server, laddr *net.UDPAddr, d *socks5.Datagram, isDNSReq bool) error {
	if isDNSReq {
		log.Infof("directly do the dns request=========================")
	}

	pc, err := dialer.ListenPacketWithOptions("udp", "", &dialer.Options{
		InterfaceName:  ss.LocalDevice(),
		InterfaceIndex: ss.LocalDeviceIndex(),
	})
	if err != nil {
		log.Errorf("listen packet err:%v", err)
		return err
	}

	dst := d.Address()
	rewrittenDst := dst
	if isDNSReq {
		rewrittenDst = DefaultDirectDNSServer
	}

	uAddr, _ := net.ResolveUDPAddr("udp", rewrittenDst)
	if _, err = pc.WriteTo(d.Data, uAddr); err != nil {
		log.Errorf("write dns request data to %s, err:%v", DefaultDirectDNSServer, err)
		return err
	}

	go func() {
		var b = udpDataBytes.Get(MaxUDPDataSize)
		defer udpDataBytes.Put(b)
		defer pc.Close()

		pc.SetReadDeadline(time.Now().Add(ss.Timeout()))

		for {
			n, _, err := pc.ReadFrom(b)
			if err != nil {
				return
			}

			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				log.Println(err)
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
