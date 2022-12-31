package easyss

import (
	"fmt"
	"net"
	"sync"

	"github.com/nange/easyss/cipherstream"
	log "github.com/sirupsen/logrus"
)

func (ss *Easyss) remoteUDPHandle(conn net.Conn, addrStr, method string) (needClose bool, err error) {
	rAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return false, fmt.Errorf("net.ResolveUDPAddr %s err:%v", addrStr, err)
	}

	uConn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return false, fmt.Errorf("net.DialUDP %v err:%v", addrStr, err)
	}

	csStream, err := cipherstream.New(conn, ss.Password(), method, "udp")
	if err != nil {
		return false, fmt.Errorf("new cipherstream err:%+v, password:%v, method:%v",
			err, ss.Password(), ss.Method())
	}

	var tryReuse bool

	wg := sync.WaitGroup{}
	wg.Add(2)
	// send
	go func() {
		defer wg.Done()

		var b = udpDataBytes.Get(MaxUDPDataSize)
		defer udpDataBytes.Put(b)
		for {
			n, err := csStream.Read(b[:])
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
			_, err = uConn.Write(b[:n])
			if err != nil {
				log.Errorf("[REMOTE_UDP] write data to remote connection err:%v", err)
				return
			}
		}
	}()

	// receive
	go func() {
		defer wg.Done()

		var b = udpDataBytes.Get(MaxUDPDataSize)
		defer udpDataBytes.Put(b)
		for {
			n, err := uConn.Read(b[:])
			if err != nil {
				log.Debugf("[REMOTE_UDP] read data from remote connection err:%v", err)
				return
			}
			_, err = csStream.Write(b[:n])
			if err != nil {
				log.Errorf("[REMOTE_UDP] write data to tcp connection err:%v", err)
				return
			}
		}
	}()

	wg.Wait()

	if tryReuse {
		setCipherDeadline(csStream, ss.Timeout())

		buf := connStateBytes.Get(32)
		defer connStateBytes.Put(buf)

		state := NewConnState(CLOSE_WAIT, buf)
		for stateFn := state.fn; stateFn != nil; {
			stateFn = stateFn(csStream).fn
		}
		if state.err != nil {
			log.Infof("[REMOTE_UDP] state err:%v, state:%v", state.err, state.state)
			markCipherStreamUnusable(csStream)
			needClose = true
		}
	} else {
		needClose = true
	}

	return needClose, nil
}
