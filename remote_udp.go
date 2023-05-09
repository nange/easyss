package easyss

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/util/bytespool"
	log "github.com/sirupsen/logrus"
)

func (es *EasyServer) remoteUDPHandle(conn net.Conn, addrStr, method string, tryReuse bool) error {
	uConn, err := es.targetConn("udp", addrStr)
	if err != nil {
		return fmt.Errorf("net.DialUDP %v err:%v", addrStr, err)
	}

	csStream, err := cipherstream.New(conn, es.Password(), method, cipherstream.FrameTypeData, cipherstream.FlagUDP)
	if err != nil {
		return fmt.Errorf("new cipherstream err:%v, method:%v", err, method)
	}

	var _tryReuse bool

	wg := sync.WaitGroup{}
	wg.Add(2)
	// send
	go func() {
		defer wg.Done()

		var buf = bytespool.Get(MaxUDPDataSize)
		defer bytespool.MustPut(buf)
		for {
			n, err := csStream.Read(buf[:])
			if err != nil {
				if errors.Is(err, cipherstream.ErrFINRSTStream) {
					_tryReuse = true
					log.Debugf("[REMOTE_UDP] received FIN when reading data from client, try to reuse the connectio")
				} else {
					log.Warnf("[REMOTE_UDP] read data from client connection err:%v", err)
				}

				uConn.Close()
				return
			}
			_, err = uConn.Write(buf[:n])
			if err != nil {
				log.Errorf("[REMOTE_UDP] write data to remote connection err:%v", err)
				return
			}
		}
	}()

	// receive
	go func() {
		defer wg.Done()

		var buf = bytespool.Get(MaxUDPDataSize)
		defer bytespool.MustPut(buf)
		for {
			n, err := uConn.Read(buf[:])
			if err != nil {
				log.Debugf("[REMOTE_UDP] read data from remote connection err:%v", err)
				return
			}
			_, err = csStream.Write(buf[:n])
			if err != nil {
				log.Errorf("[REMOTE_UDP] write data to tcp connection err:%v", err)
				return
			}
		}
	}()

	wg.Wait()

	var reuse error
	if tryReuse && _tryReuse {
		log.Debugf("[REMOTE_UDP] request is finished, try to reuse underlying tcp connection")
		reuse = tryReuseInUDPServer(csStream, es.Timeout())
	}

	if reuse != nil {
		MarkCipherStreamUnusable(csStream)
		log.Warnf("[REMOTE_UDP] underlying proxy connection is unhealthy, need close it: %v", reuse)
		return reuse
	} else {
		log.Debugf("[REMOTE_UDP] underlying proxy connection is healthy, so reuse it")
	}
	csStream.(*cipherstream.CipherStream).Release()

	return nil
}

func tryReuseInUDPServer(cipher net.Conn, timeout time.Duration) error {
	if err := cipher.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := WriteACKToCipher(cipher); err != nil {
		return err
	}
	if err := CloseWrite(cipher); err != nil {
		return err
	}
	if err := ReadACKFromCipher(cipher); err != nil {
		return err
	}
	if err := cipher.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	return nil
}
