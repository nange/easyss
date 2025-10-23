package easyss

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v2/log"
)

func (ss *Easyss) directRelay(localConn net.Conn, addr string) error {
	log.Info("[TCP_DIRECT]", "target", addr)

	tConn, err := ss.directTCPConn(addr)
	if err != nil {
		log.Warn("[TCP_DIRECT]", "dial", addr, "err", err)
		return err
	}

	wg := sync.WaitGroup{}
	wg.Go(func() {
		_, err := io.Copy(tConn, localConn)
		if err != nil && !ErrorCanIgnore(err) {
			log.Warn("[TCP_DIRECT] copy from local to remote", "err", err)
		}

		if err := CloseWrite(tConn); err != nil {
			log.Warn("[TCP_DIRECT] close write for target connection", "err", err)
		}

		_ = tConn.SetReadDeadline(time.Now().Add(ss.ReadDeadlineTimeout()))
	})
	wg.Go(func() {
		_, err := io.Copy(localConn, tConn)
		if err != nil && !ErrorCanIgnore(err) {
			log.Warn("[TCP_DIRECT] copy from remote to local", "err", err)
		}

		if err := CloseWrite(localConn); err != nil {
			log.Warn("[TCP_DIRECT] close write for local connection", "err", err)
		}

		_ = localConn.SetReadDeadline(time.Now().Add(ss.ReadDeadlineTimeout()))
	})

	wg.Wait()

	return nil
}

func (ss *Easyss) directTCPConn(addr string) (net.Conn, error) {
	var tConn net.Conn
	var err error
	network := "tcp"
	if ss.ShouldIPV6Disable() {
		network = "tcp4"
	}
	if ss.EnabledTun2socks() {
		ctx, cancel := context.WithTimeout(context.Background(), ss.Timeout())
		defer cancel()
		tConn, err = ss.directDialer.DialContext(ctx, network, addr)
	} else {
		tConn, err = net.DialTimeout(network, addr, ss.Timeout())
	}

	return tConn, err
}
