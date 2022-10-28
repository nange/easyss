package easyss

import (
	"fmt"
	"net"

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

	ch := make(chan struct{})
	// send
	go func() {
		var b [65507]byte
		for {
			n, err := csStream.Read(b[:])
			if err != nil {
				close(ch)
				log.Errorf("read udp data from tcp connection err:%v", err)
				return
			}
			_, err = uConn.Write(b[:n])
			if err != nil {
				log.Errorf("write data to remote udp connection err:%v", err)
				return
			}
		}
	}()

	// receive
	go func() {
		var b [65507]byte
		n, err := uConn.Read(b[:])
		if err != nil {
			log.Errorf("read udp data from remote udp connection err:%v", err)
			return
		}
		_, err = csStream.Write(b[:n])
		if err != nil {
			log.Errorf("write data to tcp connection err:%v", err)
			return
		}

	}()

	<-ch
	uConn.Close()

	return true, nil
}
