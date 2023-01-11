package easyss

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/nange/easyss/util/bytespool"
	log "github.com/sirupsen/logrus"
	"github.com/xjasonlyu/tun2socks/v2/component/dialer"
)

func (ss *Easyss) directRelay(localConn net.Conn, addr string) error {
	log.Infof("[TCP_DIRECT] target:%s", addr)

	tConn, err := ss.directTCPConn(addr)
	if err != nil {
		log.Warnf("[TCP_DIRECT] dial:%s err:%v", addr, err)
		return err
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		buf := bytespool.Get(RelayBufferSize)
		defer bytespool.MustPut(buf)
		_, err := io.CopyBuffer(tConn, localConn, buf)
		if err != nil && !ErrorCanIgnore(err) {
			log.Warnf("[TCP_DIRECT] copy from local to remote err:%v", err)
		}

		if err := tConn.(*net.TCPConn).CloseWrite(); err != nil && !ErrorCanIgnore(err) {
			log.Warnf("[TCP_DIRECT] close write for target connection:%v", err)
		}

	}()

	go func() {
		defer wg.Done()

		buf := bytespool.Get(RelayBufferSize)
		defer bytespool.MustPut(buf)
		_, err := io.CopyBuffer(localConn, tConn, buf)
		if err != nil && !ErrorCanIgnore(err) {
			log.Warnf("[TCP_DIRECT] copy from remote to local err:%v", err)
		}

		if err := localConn.(*net.TCPConn).CloseWrite(); err != nil && !ErrorCanIgnore(err) {
			log.Warnf("[TCP_DIRECT] close write for local connection:%v", err)
		}
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
