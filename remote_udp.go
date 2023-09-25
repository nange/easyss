package easyss

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
)

func (es *EasyServer) remoteUDPHandle(conn net.Conn, addrStr, method string, isDNSProto, tryReuse bool) error {
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
					log.Debug("[REMOTE_UDP] received FIN when reading data from client, try to reuse the connection")
				} else {
					log.Warn("[REMOTE_UDP] read data from client connection", "err", err)
				}

				uConn.Close()
				return
			}
			if isDNSProto {
				// try to parse the dns request
				msg := &dns.Msg{}
				if err := msg.Unpack(buf[:n]); err == nil {
					log.Info("[REMOTE_UDP] doing dns request for", "target", msg.Question[0].Name)
				}
			}
			_, err = uConn.Write(buf[:n])
			if err != nil {
				log.Error("[REMOTE_UDP] write data to remote connection", "err", err)
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
				log.Debug("[REMOTE_UDP] read data from remote connection", "err", err)
				return
			}
			_, err = csStream.Write(buf[:n])
			if err != nil {
				log.Error("[REMOTE_UDP] write data to tcp connection", "err", err)
				return
			}
		}
	}()

	wg.Wait()

	var reuse error
	if tryReuse && _tryReuse {
		log.Debug("[REMOTE_UDP] request is finished, try to reuse underlying tcp connection")
		reuse = tryReuseInUDPServer(csStream, es.Timeout())
	}

	if reuse != nil {
		MarkCipherStreamUnusable(csStream)
		log.Warn("[REMOTE_UDP] underlying proxy connection is unhealthy, need close it", "reuse", reuse)
		return reuse
	} else {
		log.Debug("[REMOTE_UDP] underlying proxy connection is healthy, so reuse it")
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
