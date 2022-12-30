package easyss

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/xjasonlyu/tun2socks/v2/component/dialer"
)

func (ss *Easyss) directRelay(localConn net.Conn, addr string) error {
	log.Infof("directly relay tcp request for addr:%s", addr)

	tConn, err := ss.directTCPConn(addr)
	if err != nil {
		log.Errorf("directly dial addr:%s err:%v", addr, err)
		return err
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(tConn, localConn)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Warnf("reading from local conn write to remote err:%v", err)
		}
		tConn.Close()
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(localConn, tConn)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Warnf("reading from remote conn write to local err:%v", err)
		}
		localConn.Close()
	}()

	wg.Wait()

	return nil
}

func (ss *Easyss) directTCPConn(addr string) (net.Conn, error) {
	var tConn net.Conn
	var err error
	if ss.EnabledTun2socks() {
		ctx, cancel := context.WithTimeout(context.Background(), ss.Timeout())
		defer cancel()
		tConn, err = dialer.DialContextWithOptions(ctx, "tcp", addr, &dialer.Options{
			InterfaceName:  ss.LocalDevice(),
			InterfaceIndex: ss.LocalDeviceIndex(),
		})
	} else {
		tConn, err = net.DialTimeout("tcp", addr, ss.Timeout())
	}

	return tConn, err
}
