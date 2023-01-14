package easyss

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
	"github.com/nange/easyss/util/bytespool"
	log "github.com/sirupsen/logrus"
)

func (ss *Easyss) remoteUDPHandle(conn net.Conn, addrStr, method string) error {
	rAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return fmt.Errorf("net.ResolveUDPAddr %s err:%v", addrStr, err)
	}

	uConn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return fmt.Errorf("net.DialUDP %v err:%v", addrStr, err)
	}

	csStream, err := cipherstream.New(conn, ss.Password(), method, util.FrameTypeData, util.FlagUDP)
	if err != nil {
		return fmt.Errorf("new cipherstream err:%+v, password:%v, method:%v",
			err, ss.Password(), ss.Method())
	}

	var tryReuse bool

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
				if cipherstream.FINRSTStreamErr(err) {
					tryReuse = true
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

	var reuse bool
	if tryReuse {
		log.Debugf("[REMOTE_UDP] request is finished, try to reuse underlying tcp connection")
		reuse = tryReuseInUDPServer(csStream, ss.Timeout())
	}

	if !reuse {
		MarkCipherStreamUnusable(csStream)
		log.Infof("[REMOTE_UDP] underlying proxy connection is unhealthy, need close it")
	} else {
		log.Infof("[REMOTE_UDP] underlying proxy connection is healthy, so reuse it")
	}
	csStream.(*cipherstream.CipherStream).Release()

	return nil
}

func tryReuseInUDPServer(cipher net.Conn, timeout time.Duration) bool {
	if err := SetCipherDeadline(cipher, timeout); err != nil {
		return false
	}
	if err := WriteACKToCipher(cipher); err != nil {
		return false
	}
	if err := CloseWrite(cipher); err != nil {
		return false
	}
	if !ReadACKFromCipher(cipher) {
		return false
	}
	if err := cipher.SetDeadline(time.Time{}); err != nil {
		return false
	}

	return true
}
