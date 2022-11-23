package easyss

import (
	"context"
	"io"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/xjasonlyu/tun2socks/v2/component/dialer"
)

func (ss *Easyss) directRelay(localConn net.Conn, addr string) error {
	log.Debugf("directly relay tcp proto for addr:%s", addr)

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
