package easyss

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/nange/easyss/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/dialer"
)

func (ss *Easyss) directRelay(localConn net.Conn, addr string) error {
	log.Info("[TCP_DIRECT]", "target", addr)

	tConn, err := ss.directTCPConn(addr)
	if err != nil {
		log.Warn("[TCP_DIRECT]", "dial", addr, "err", err)
		return err
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		_, err := io.Copy(tConn, localConn)
		if err != nil && !ErrorCanIgnore(err) {
			log.Warn("[TCP_DIRECT] copy from local to remote", "err", err)
		}

		if err := CloseWrite(tConn); err != nil {
			log.Warn("[TCP_DIRECT] close write for target connection", "err", err)
		}

	}()

	go func() {
		defer wg.Done()

		_, err := io.Copy(localConn, tConn)
		if err != nil && !ErrorCanIgnore(err) {
			log.Warn("[TCP_DIRECT] copy from remote to local", "err", err)
		}

		if err := CloseWrite(localConn); err != nil {
			log.Warn("[TCP_DIRECT] close write for local connection", "err", err)
		}
	}()

	wg.Wait()

	return nil
}

func (ss *Easyss) directTCPConn(addr string) (net.Conn, error) {
	var tConn net.Conn
	var err error
	network := "tcp"
	if ss.DisableIPV6() {
		network = "tcp4"
	}
	if ss.EnabledTun2socks() {
		ctx, cancel := context.WithTimeout(context.Background(), ss.Timeout())
		defer cancel()
		tConn, err = dialer.DialContextWithOptions(ctx, network, addr, &dialer.Options{
			InterfaceName:  ss.LocalDevice(),
			InterfaceIndex: ss.LocalDeviceIndex(),
		})
	} else {
		tConn, err = net.DialTimeout(network, addr, ss.Timeout())
	}

	return tConn, err
}
